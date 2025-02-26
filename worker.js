/**
 * 改进后的 Cloudflare Workers 脚本
 *
 * 功能：
 *  - API 接口：
 *      - GET /v1/models 返回模型列表
 *      - POST /v1/chat/completions 发送消息（需 API 密钥验证）
 *      - POST /v1/rate-limits 检查调用频率
 *  - 配置管理页面：
 *      - /config 系列接口，通过环境变量 CONFIG_PASSWORD 控制访问
 *      - 加载页面时，对每个 cookie 验证所有模型状态，
 *        并在页面中显示每个 cookie 的状态以及各模型状态，同时对过长的 Cookie 进行截断显示
 *
 * 使用 D1 SQL 数据库存储配置（表名：config，操作 id=1 的记录）
 */

const TARGET_URL = "https://grok.com/rest/app-chat/conversations/new";
const CHECK_URL = "https://grok.com/rest/rate-limits";
const MODELS = ["grok-2", "grok-3", "grok-3-thinking"];
const MODELS_TO_CHECK = ["grok-2", "grok-3", "grok-3-thinking"];
const USER_AGENTS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.2420.81",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0.1 Safari/605.1.15",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:132.0) Gecko/20100101 Firefox/132.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:124.0) Gecko/20100101 Firefox/124.0",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
  "Mozilla/5.0 (X11; Linux i686; rv:124.0) Gecko/20100101 Firefox/124.0",
];

/* ========== 辅助函数：请求超时 ========== */
async function fetchWithTimeout(url, options, timeout = 5000) {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("请求超时")), timeout)
    ),
  ]);
}

/* ========== 辅助函数：截断过长的 Cookie ========== */
function truncateCookie(cookie) {
  const maxLen = 30;
  if (cookie.length > maxLen) {
    return cookie.slice(0, 10) + "..." + cookie.slice(-10);
  }
  return cookie;
}

/* ========== 数据库操作封装 ========== */
async function getConfig(env) {
  await env.D1_DB.prepare(
    `CREATE TABLE IF NOT EXISTS config (
      id INTEGER PRIMARY KEY,
      data TEXT NOT NULL
    )`
  ).run();

  let row = await env.D1_DB.prepare("SELECT data FROM config WHERE id = 1").first();
  if (row && row.data) {
    try {
      return JSON.parse(row.data);
    } catch (e) {
      console.error("配置 JSON 解析错误:", e);
    }
  }
  const defaultConfig = {
    cookies: [],
    last_cookie_index: { "grok-2": 0, "grok-3": 0, "grok-3-thinking": 0 },
    temporary_mode: true,
  };
  await setConfig(defaultConfig, env);
  return defaultConfig;
}

async function setConfig(config, env) {
  const jsonStr = JSON.stringify(config);
  await env.D1_DB.prepare("REPLACE INTO config (id, data) VALUES (1, ?)")
    .bind(jsonStr)
    .run();
}

/* ========== Cookie 轮询 ========== */
async function getNextAccount(model, env) {
  let config = await getConfig(env);
  if (!config.cookies || config.cookies.length === 0) {
    throw new Error("没有可用的 cookie，请先通过配置页面添加。");
  }
  const num = config.cookies.length;
  const current = ((config.last_cookie_index[model] || 0) + 1) % num;
  config.last_cookie_index[model] = current;
  await setConfig(config, env);
  return config.cookies[current];
}

/* ========== 请求头封装 ========== */
function getCommonHeaders(cookie) {
  return {
    "Accept": "*/*",
    "Content-Type": "application/json",
    "Origin": "https://grok.com",
    "Referer": "https://grok.com/",
    "Cookie": cookie,
    "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)],
  };
}

/* ========== 检查调用频率 ========== */
/**
 * 使用指定 cookie 调用 CHECK_URL 接口，返回 JSON 数据（带超时保护）
 */
async function checkRateLimitWithCookie(model, cookie, isReasoning) {
  const headers = getCommonHeaders(cookie);
  const payload = {
    requestKind: isReasoning ? "REASONING" : "DEFAULT",
    modelName: model,
  };
  const response = await fetchWithTimeout(CHECK_URL, {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    throw new Error(`Rate limit check failed for model ${model}, status: ${response.status}`);
  }
  return await response.json();
}

/**
 * 检查单个 cookie 的状态：
 *  - expired：如果用模型 "grok-2" 测试失败，则认为该 cookie 已过期
 *  - 对 MODELS_TO_CHECK 中的模型检查剩余查询次数，返回数组 rateLimitDetails
 *
 * 优化：对 "grok-2" 的调用只做一次，作为过期检测及剩余次数检测
 */
async function checkCookieStatus(cookie) {
  let rateLimitDetails = [];
  try {
    // 先测试 grok-2
    const dataGrok2 = await checkRateLimitWithCookie("grok-2", cookie, false);
    rateLimitDetails.push({ model: "grok-2", remainingQueries: dataGrok2.remainingQueries });
  } catch (e) {
    return { expired: true, rateLimited: false, rateLimitDetails: [] };
  }
  // 再检查 grok-3
  try {
    const dataGrok3 = await checkRateLimitWithCookie("grok-3", cookie, false);
    rateLimitDetails.push({ model: "grok-3", remainingQueries: dataGrok3.remainingQueries });
  } catch (e) {
    rateLimitDetails.push({ model: "grok-3", error: e.toString(), remainingQueries: 0 });
  }
  // 检查 grok-3-thinking
  try {
    const dataGrok3Thinking = await checkRateLimitWithCookie("grok-3", cookie, true);
    rateLimitDetails.push({ model: "grok-3-thinking", remainingQueries: dataGrok3Thinking.remainingQueries });
  } catch (e) {
    rateLimitDetails.push({ model: "grok-3-thinking", error: e.toString(), remainingQueries: 0 });
  }
  const rateLimited = rateLimitDetails.every(detail => detail.remainingQueries === 0);
  return { expired: false, rateLimited, rateLimitDetails };
}

/* ========== 消息预处理 ========== */
function magic(messages) {
  let disableSearch = false;
  let forceConcise = false;
  if (messages && messages.length > 0) {
    let first = messages[0].content;
    if (first.includes("<|disableSearch|>")) {
      disableSearch = true;
      first = first.replace(/<\|disableSearch\|>/g, "");
    }
    if (first.includes("<|forceConcise|>")) {
      forceConcise = true;
      first = first.replace(/<\|forceConcise\|>/g, "");
    }
    messages[0].content = first;
  }
  return { disableSearch, forceConcise, messages };
}

function formatMessage(messages) {
  let roleMap = { user: "Human", assistant: "Assistant", system: "System" };
  const roleInfoPattern = /<roleInfo>\s*user:\s*([^\n]*)\s*assistant:\s*([^\n]*)\s*system:\s*([^\n]*)\s*prefix:\s*([^\n]*)\s*<\/roleInfo>\n/;
  let prefix = false;
  let firstContent = messages[0].content;
  let match = firstContent.match(roleInfoPattern);
  if (match) {
    roleMap = {
      user: match[1],
      assistant: match[2],
      system: match[3],
    };
    prefix = match[4] === "1";
    messages[0].content = firstContent.replace(roleInfoPattern, "");
  }
  let formatted = "";
  for (const msg of messages) {
    let role = prefix ? "\b" + roleMap[msg.role] : roleMap[msg.role];
    formatted += `${role}: ${msg.content}\n`;
  }
  return formatted;
}

/* ========== API 接口 ========== */
async function handleModels() {
  const data = MODELS.map((model) => ({
    id: model,
    object: "model",
    created: Math.floor(Date.now() / 1000),
    owned_by: "Elbert",
    name: model,
  }));
  return new Response(JSON.stringify({ object: "list", data }), {
    headers: { "Content-Type": "application/json" },
  });
}

async function handleChatCompletions(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Missing or invalid Authorization header" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  const token = authHeader.split(" ")[1];
  if (token !== env.CONFIG_PASSWORD) {
    return new Response(JSON.stringify({ error: "Invalid API key" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  try {
    const reqJson = await request.json();
    const streamFlag = reqJson.stream || false;
    const messages = reqJson.messages;
    let model = reqJson.model;
    if (!MODELS.includes(model)) {
      return new Response(JSON.stringify({ error: "模型不可用" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (!messages) {
      return new Response(JSON.stringify({ error: "必须提供消息" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
    const { disableSearch, forceConcise, messages: newMessages } = magic(messages);
    const formattedMessage = formatMessage(newMessages);
    const isReasoning = model.length > 6;
    model = model.substring(0, 6);
    if (streamFlag) {
      return await sendMessageStream(formattedMessage, model, disableSearch, forceConcise, isReasoning, env);
    } else {
      return await sendMessageNonStream(formattedMessage, model, disableSearch, forceConcise, isReasoning, env);
    }
  } catch (e) {
    console.error("处理 chat completions 出错:", e);
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

/* ========== 检查调用频率 ========== */
async function handleRateLimits(request, env) {
  try {
    const reqJson = await request.json();
    const model = reqJson.model;
    const isReasoning = !!reqJson.isReasoning;
    if (!MODELS.includes(model)) {
      return new Response(JSON.stringify({ error: "模型不可用" }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
    return await checkRateLimit(model, isReasoning, env);
  } catch (e) {
    console.error("检查调用频率出错:", e);
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

async function checkRateLimit(model, isReasoning, env) {
  let cookie;
  try {
    cookie = await getNextAccount(model, env);
  } catch (e) {
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const headers = getCommonHeaders(cookie);
  const payload = {
    requestKind: isReasoning ? "REASONING" : "DEFAULT",
    modelName: model,
  };
  try {
    const response = await fetchWithTimeout(CHECK_URL, {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      throw new Error("调用频率检查失败");
    }
    const data = await response.json();
    return new Response(JSON.stringify(data), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    console.error("调用频率检查异常:", e);
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

/* ========== 流式消息转发 ========== */
async function sendMessageStream(message, model, disableSearch, forceConcise, isReasoning, env) {
  let cookie;
  try {
    cookie = await getNextAccount(model, env);
  } catch (e) {
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const headers = getCommonHeaders(cookie);
  const config = await getConfig(env);
  const payload = {
    temporary: config.temporary_mode,
    modelName: model,
    message: message,
    fileAttachments: [],
    imageAttachments: [],
    disableSearch: disableSearch,
    enableImageGeneration: false,
    returnImageBytes: false,
    returnRawGrokInXaiRequest: false,
    enableImageStreaming: true,
    imageGenerationCount: 2,
    forceConcise: forceConcise,
    toolOverrides: {},
    enableSideBySide: true,
    isPreset: false,
    sendFinalMetadata: true,
    customInstructions: "",
    deepsearchPreset: "",
    isReasoning: isReasoning,
  };
  const init = {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  };
  const response = await fetchWithTimeout(TARGET_URL, init);
  if (!response.ok) {
    return new Response(JSON.stringify({ error: "发送消息失败" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 使用 ReadableStream 优化流数据处理
  const stream = new ReadableStream({
    async start(controller) {
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      const encoder = new TextEncoder();
      let buffer = "";
      let thinking = 2;
      let batchSize = 0;
      let batchContent = "";
      const MAX_BATCH_SIZE = 5;
      const BATCH_INTERVAL = 50;
      let lastBatchTime = Date.now();

      const processBatch = async () => {
        if (batchContent) {
          const chunkData = {
            id: "chatcmpl-" + crypto.randomUUID(),
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: model,
            choices: [
              { index: 0, delta: { content: batchContent }, finish_reason: null },
            ],
          };
          controller.enqueue(encoder.encode("data: " + JSON.stringify(chunkData) + "\n\n"));
          batchContent = "";
          batchSize = 0;
        }
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split("\n");
        buffer = lines.pop();

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          try {
            const data = JSON.parse(trimmed);
            if (!data?.result?.response || typeof data.result.response.token !== "string") {
              continue;
            }

            let token = data.result.response.token;
            let content = token;

            if (isReasoning) {
              if (thinking === 2) {
                thinking = 1;
                content = `<Thinking>\n${token}`;
              } else if (thinking === 1 && !data.result.response.isThinking) {
                thinking = 0;
                content = `\n</Thinking>\n${token}`;
              }
            }

            batchContent += content;
            batchSize++;

            // 当达到批处理阈值或距离上次发送已经过了足够时间时，发送数据
            const now = Date.now();
            if (batchSize >= MAX_BATCH_SIZE || (now - lastBatchTime >= BATCH_INTERVAL && batchContent)) {
              await processBatch();
              lastBatchTime = now;
              // 添加微小延迟，让出 CPU
              await new Promise(resolve => setTimeout(resolve, 1));
            }

            if (data.result.response.isSoftStop) {
              await processBatch(); // 处理剩余的批次
              const finalChunk = {
                id: "chatcmpl-" + crypto.randomUUID(),
                object: "chat.completion.chunk",
                created: Math.floor(Date.now() / 1000),
                model: model,
                choices: [
                  { index: 0, delta: { content: "" }, finish_reason: "completed" },
                ],
              };
              controller.enqueue(encoder.encode("data: " + JSON.stringify(finalChunk) + "\n\n"));
              controller.close();
              return;
            }
          } catch (e) {
            console.error("JSON 解析错误:", e, "行内容:", trimmed);
          }
        }
      }

      // 处理剩余的缓冲区数据
      if (buffer.trim() !== "") {
        try {
          const data = JSON.parse(buffer.trim());
          if (data?.result?.response && typeof data.result.response.token === "string") {
            let token = data.result.response.token;
            let content = token;
            if (isReasoning) {
              if (thinking === 2) {
                thinking = 1;
                content = `<Thinking>\n${token}`;
              } else if (thinking === 1 && !data.result.response.isThinking) {
                thinking = 0;
                content = `\n</Thinking>\n${token}`;
              }
            }
            batchContent += content;
          }
        } catch (e) {
          console.error("Final JSON parse error:", e, "in buffer:", buffer);
        }
      }

      // 处理最后的批次
      await processBatch();
      controller.enqueue(encoder.encode("data: [DONE]\n\n"));
      controller.close();
    }
  });

  return new Response(stream, {
    headers: { "Content-Type": "text/event-stream" },
  });
}

/* ========== 非流式消息转发 ========== */
async function sendMessageNonStream(message, model, disableSearch, forceConcise, isReasoning, env) {
  let cookie;
  try {
    cookie = await getNextAccount(model, env);
  } catch (e) {
    return new Response(JSON.stringify({ error: e.toString() }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const headers = getCommonHeaders(cookie);
  const config = await getConfig(env);
  const payload = {
    temporary: config.temporary_mode,
    modelName: model,
    message: message,
    fileAttachments: [],
    imageAttachments: [],
    disableSearch: disableSearch,
    enableImageGeneration: false,
    returnImageBytes: false,
    returnRawGrokInXaiRequest: false,
    enableImageStreaming: true,
    imageGenerationCount: 2,
    forceConcise: forceConcise,
    toolOverrides: {},
    enableSideBySide: true,
    isPreset: false,
    sendFinalMetadata: true,
    customInstructions: "",
    deepsearchPreset: "",
    isReasoning: isReasoning,
  };
  const init = {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
  };
  const response = await fetchWithTimeout(TARGET_URL, init);
  if (!response.ok) {
    return new Response(JSON.stringify({ error: "发送消息失败" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const fullText = await response.text();
  let finalMessage = "";
  const lines = fullText.split("\n").filter(line => line.trim() !== "");
  for (const line of lines) {
    try {
      const data = JSON.parse(line);
      if (data?.result?.response) {
        if (data.result.response.modelResponse && data.result.response.modelResponse.message) {
          finalMessage = data.result.response.modelResponse.message;
          break;
        } else if (typeof data.result.response.token === "string") {
          finalMessage += data.result.response.token;
        }
      }
    } catch (e) {
      console.error("JSON 解析错误:", e, "行内容:", line);
    }
  }
  const openai_response = {
    id: "chatcmpl-" + crypto.randomUUID(),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: model,
    choices: [
      { index: 0, message: { role: "assistant", content: finalMessage }, finish_reason: "completed" },
    ],
  };
  return new Response(JSON.stringify(openai_response), {
    headers: { "Content-Type": "application/json" },
  });
}

/* ========== 登录与认证 ========== */
async function requireAuth(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/config_auth=([^;]+)/);
  if (match && match[1] === env.CONFIG_PASSWORD) {
    return true;
  }
  return false;
}

function loginPage() {
  const html = 
  `<!DOCTYPE html>
  <html>
  <head>
    <meta charset="UTF-8">
    <title>登录配置管理</title>
    <style>
      body { font-family: Arial, sans-serif; background: #f0f2f5; display: flex; align-items: center; justify-content: center; height: 100vh; }
      .login-container { background: #fff; padding: 20px 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
      h2 { margin-bottom: 20px; }
      input[type="password"] { width: 100%; padding: 8px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }
      button { background: #007BFF; color: #fff; border: none; padding: 10px; border-radius: 4px; cursor: pointer; width: 100%; }
      button:hover { background: #0056b3; }
    </style>
  </head>
  <body>
    <div class="login-container">
      <h2>请输入密码</h2>
      <form method="POST" action="/config/login">
        <input type="password" name="password" placeholder="密码" required>
        <button type="submit">登录</button>
      </form>
    </div>
  </body>
  </html>`;
  return new Response(html, { headers: { "Content-Type": "text/html" } });
}

async function handleLogin(request, env) {
  const formData = await request.formData();
  const password = formData.get("password") || "";
  if (password === env.CONFIG_PASSWORD) {
    const redirectURL = new URL("/config", request.url).toString();
    const urlObj = new URL(request.url);
    const isHttps = urlObj.protocol === "https:";
    const cookieHeader = `config_auth=${env.CONFIG_PASSWORD}; Path=/; HttpOnly; ${isHttps ? "Secure; " : ""}SameSite=Strict`;
    return new Response("", {
      status: 302,
      headers: {
        "Set-Cookie": cookieHeader,
        "Location": redirectURL,
      },
    });
  } else {
    return new Response("密码错误", { status: 401 });
  }
}

/* ========== 配置管理页面 ========== */
async function configPage(request, env) {
  const config = await getConfig(env);
  let cookieStatuses = [];
  try {
    cookieStatuses = await Promise.all(
      config.cookies.map(cookie =>
        checkCookieStatus(cookie).catch(e => ({ expired: true, rateLimited: false, rateLimitDetails: [] }))
      )
    );
  } catch (e) {
    console.error("Error checking cookie statuses:", e);
  }
  
  const tableRows = config.cookies.map((cookie, index) => {
    const status = cookieStatuses[index] || { expired: true, rateLimited: false, rateLimitDetails: [] };
    const cookieStateHtml = status.expired 
                              ? '<span style="color:red;">已过期</span>' 
                              : '<span style="color:green;">有效</span>';
    const rateLimitHtml = status.expired 
                              ? '--'
                              : status.rateLimitDetails.map(detail => {
                                  if (detail.error) {
                                    return `${detail.model}: <span style="color:red;">错误(${detail.error})</span>`;
                                  } else {
                                    return detail.remainingQueries > 0 
                                      ? `${detail.model}: <span style="color:green;">有效 (剩余: ${detail.remainingQueries})</span>`
                                      : `${detail.model}: <span style="color:red;">限额已达</span>`;
                                  }
                                }).join(" | ");
    return `<tr>
      <td>${index + 1}</td>
      <td>${truncateCookie(cookie)}</td>
      <td>${cookieStateHtml}</td>
      <td>${rateLimitHtml}</td>
      <td>
         <form method="POST" action="/config" class="form-inline">
            <input type="hidden" name="action" value="delete_one">
            <input type="hidden" name="index" value="${index}">
            <button type="submit" class="btn-danger">删除</button>
         </form>
      </td>
    </tr>`;
  }).join('');
  
  const html = 
  `<!DOCTYPE html>
  <html>
    <head>
      <meta charset="UTF-8">
      <title>配置管理</title>
      <style>
        body { font-family: Arial, sans-serif; background: #f9f9f9; margin: 0; padding: 20px; }
        .container { max-width: 900px; margin: auto; background: #fff; padding: 20px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1); }
        h1 { text-align: center; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; word-break: break-all; }
        th { background: #f2f2f2; }
        form { margin: 0; }
        .actions { display: flex; gap: 8px; margin-top: 20px; }
        button { background: #28a745; color: #fff; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; }
        button:hover { background: #218838; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .btn-toggle { background: #17a2b8; }
        .btn-toggle:hover { background: #138496; }
        .form-inline { display: flex; align-items: center; gap: 10px; }
        input[type="text"] { flex: 1; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>配置管理</h1>
        <p><strong>API Key:</strong> 与配置密码相同</p>
        <h2>当前 Cookies</h2>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Cookie</th>
              <th>Cookie状态</th>
              <th>模型状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            ${tableRows}
          </tbody>
        </table>
        <p>Temporary Mode: <strong>${config.temporary_mode ? "开启" : "关闭"}</strong></p>
        <hr>
        <h2>添加 Cookie</h2>
        <form method="POST" action="/config" class="form-inline">
          <input type="hidden" name="action" value="add">
          <input type="text" name="cookie" placeholder="请输入 Cookie" required>
          <button type="submit">添加</button>
        </form>
        <hr>
        <h2>全局操作</h2>
        <div class="actions">
          <form method="POST" action="/config">
            <input type="hidden" name="action" value="delete">
            <button type="submit" class="btn-danger">删除所有 Cookies</button>
          </form>
          <form method="POST" action="/config">
            <input type="hidden" name="action" value="toggle">
            <button type="submit" class="btn-toggle">切换 Temporary Mode</button>
          </form>
        </div>
      </div>
    </body>
  </html>`;
  return new Response(html, { headers: { "Content-Type": "text/html" } });
}

async function updateConfig(request, env) {
  const formData = await request.formData();
  const action = formData.get("action");
  const config = await getConfig(env);
  if (action === "add") {
    const newCookie = formData.get("cookie");
    if (newCookie && newCookie.trim() !== "") {
      config.cookies.push(newCookie.trim());
    }
  } else if (action === "delete") {
    config.cookies = [];
  } else if (action === "toggle") {
    config.temporary_mode = !config.temporary_mode;
  } else if (action === "delete_one") {
    const index = parseInt(formData.get("index"), 10);
    if (!isNaN(index) && index >= 0 && index < config.cookies.length) {
      config.cookies.splice(index, 1);
    }
  }
  await setConfig(config, env);
  return Response.redirect(new URL("/config", request.url).toString(), 302);
}

/* ========== 主调度函数 ========== */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === "/" || url.pathname === "") {
      return Response.redirect(new URL("/config", request.url).toString(), 302);
    }
    
    if (url.pathname.startsWith("/config")) {
      if (url.pathname === "/config/login") {
        if (request.method === "GET") {
          return loginPage();
        } else if (request.method === "POST") {
          return handleLogin(request, env);
        }
      }
      if (!(await requireAuth(request, env))) {
        return Response.redirect(new URL("/config/login", request.url).toString(), 302);
      }
      if (request.method === "GET") {
        return configPage(request, env);
      } else if (request.method === "POST") {
        return updateConfig(request, env);
      }
    } else if (url.pathname.startsWith("/v1/models")) {
      return handleModels();
    } else if (url.pathname.startsWith("/v1/rate-limits")) {
      return handleRateLimits(request, env);
    } else if (url.pathname.startsWith("/v1/chat/completions")) {
      return handleChatCompletions(request, env);
    }
    return new Response("Not Found", { status: 404 });
  }
};
