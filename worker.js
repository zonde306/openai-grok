/**
 * Cloudflare Workers 脚本
 *
 * 使用 D1 SQL 数据库存储配置（表名：config, 仅操作 id=1 的记录）
 *
 * API 接口：
 *  - GET /v1/models 返回模型列表
 *  - POST /v1/chat/completions 发送消息
 *
 * 配置管理页面：
 *  - 访问 /config 时需要密码验证，密码由环境变量 CONFIG_PASSWORD 设置
 *  - 未登录时重定向到 /config/login，登录成功后写入 Cookie
 */

const TARGET_URL = "https://grok.com/rest/app-chat/conversations/new";
const MODELS = ["grok-2", "grok-3", "grok-3-thinking"];
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

/* ========== 数据库操作封装 ========== */
async function getConfig(env) {
  // 创建表(如果不存在)
  await env.D1_DB.prepare(`
    CREATE TABLE IF NOT EXISTS config (
      id INTEGER PRIMARY KEY,
      data TEXT NOT NULL
    )
  `).run();

  // 尝试从 id=1 的记录中读取配置
  let row = await env.D1_DB.prepare("SELECT data FROM config WHERE id = 1").first();
  if (row && row.data) {
    try {
      return JSON.parse(row.data);
    } catch (e) {
      console.error("配置 JSON 解析错误:", e);
    }
  }
  // 如果不存在则返回默认配置，并写入数据库
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
  // 使用 REPLACE INTO 保证 id=1 的记录存在
  await env.D1_DB.prepare(
    "REPLACE INTO config (id, data) VALUES (1, ?)"
  ).bind(jsonStr).run();
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
    // reasoning 模式判断：若模型名称长度大于6，则认为是 reasoning 模式，同时取前6字符
    const isReasoning = model.length > 6;
    model = model.substring(0, 6);
    if (streamFlag) {
      return await sendMessageStream(formattedMessage, model, disableSearch, forceConcise, isReasoning, env);
    } else {
      return await sendMessageNonStream(formattedMessage, model, disableSearch, forceConcise, isReasoning, env);
    }
  } catch (e) {
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
  const headers = {
    Accept: "*/*",
    "Content-Type": "application/json",
    Origin: "https://grok.com",
    Referer: "https://grok.com/",
    Cookie: cookie,
    "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)],
  };
  const payload = {
    temporary: true,
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
  const response = await fetch(TARGET_URL, init);
  if (!response.ok) {
    return new Response(JSON.stringify({ error: "发送消息失败" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const reader = response.body.getReader();

  async function pump() {
    let thinking = 2;
    let buffer = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      // 按换行符分割，确保每行是完整的 JSON 字符串
      let lines = buffer.split("\n");
      buffer = lines.pop(); // 保留最后不完整的部分
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
          const chunkData = {
            id: "chatcmpl-" + crypto.randomUUID(),
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: model,
            choices: [
              { index: 0, delta: { content: content }, finish_reason: null },
            ],
          };
          await writer.write(encoder.encode("data: " + JSON.stringify(chunkData) + "\n\n"));
          if (data.result.response.isSoftStop) {
            const finalChunk = {
              id: "chatcmpl-" + crypto.randomUUID(),
              object: "chat.completion.chunk",
              created: Math.floor(Date.now() / 1000),
              model: model,
              choices: [
                { index: 0, delta: { content: content }, finish_reason: "completed" },
              ],
            };
            await writer.write(encoder.encode("data: " + JSON.stringify(finalChunk) + "\n\n"));
            writer.close();
            return;
          }
        } catch (e) {
          console.error("JSON parse error:", e, "in line:", trimmed);
        }
      }
    }
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
          const chunkData = {
            id: "chatcmpl-" + crypto.randomUUID(),
            object: "chat.completion.chunk",
            created: Math.floor(Date.now() / 1000),
            model: model,
            choices: [
              { index: 0, delta: { content: content }, finish_reason: null },
            ],
          };
          await writer.write(encoder.encode("data: " + JSON.stringify(chunkData) + "\n\n"));
        }
      } catch (e) {
        console.error("Final JSON parse error:", e, "in buffer:", buffer);
      }
    }
    await writer.write(encoder.encode("data: [DONE]\n\n"));
    writer.close();
  }
  pump();
  return new Response(readable, {
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
  const headers = {
    Accept: "*/*",
    "Content-Type": "application/json",
    Origin: "https://grok.com",
    Referer: "https://grok.com/",
    Cookie: cookie,
    "User-Agent": USER_AGENTS[Math.floor(Math.random() * USER_AGENTS.length)],
  };
  const payload = {
    temporary: true,
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
  const response = await fetch(TARGET_URL, init);
  if (!response.ok) {
    return new Response(JSON.stringify({ error: "发送消息失败" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
  const fullText = await response.text();
  const openai_response = {
    id: "chatcmpl-" + crypto.randomUUID(),
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: model,
    choices: [
      { index: 0, message: { role: "assistant", content: fullText }, finish_reason: "completed" },
    ],
  };
  return new Response(JSON.stringify(openai_response), {
    headers: { "Content-Type": "application/json" },
  });
}

/* ========== 登录与认证 ========== */
// 检查请求 Cookie 是否包含正确的认证信息
async function requireAuth(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/config_auth=([^;]+)/);
  if (match && match[1] === env.CONFIG_PASSWORD) {
    return true;
  }
  return false;
}

// 登录页面（美化版）
function loginPage() {
  const html = `
  <!DOCTYPE html>
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
  </html>
  `;
  return new Response(html, { headers: { "Content-Type": "text/html" } });
}

// 处理登录请求
async function handleLogin(request, env) {
  const formData = await request.formData();
  const password = formData.get("password") || "";
  if (password === env.CONFIG_PASSWORD) {
    // 构造绝对 URL 重定向
    const redirectURL = new URL("/config", request.url).toString();
    return new Response("", {
      status: 302,
      headers: {
        "Set-Cookie": `config_auth=${env.CONFIG_PASSWORD}; Path=/; HttpOnly; Secure; SameSite=Strict`,
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
  const html = `
  <!DOCTYPE html>
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
        <h2>当前 Cookies</h2>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Cookie</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            ${config.cookies.map((cookie, index) => `
              <tr>
                <td>${index + 1}</td>
                <td>${cookie}</td>
                <td>
                  <form method="POST" action="/config" class="form-inline">
                    <input type="hidden" name="action" value="delete_one">
                    <input type="hidden" name="index" value="${index}">
                    <button type="submit" class="btn-danger">删除</button>
                  </form>
                </td>
              </tr>
            `).join('')}
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
  </html>
  `;
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
  // 构造绝对 URL 重定向
  return Response.redirect(new URL("/config", request.url).toString(), 302);
}

/* ========== 主调度函数 ========== */
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    // 根路径重定向到 /config
    if (url.pathname === "/" || url.pathname === "") {
      return Response.redirect(new URL("/config", request.url).toString(), 302);
    }
    
    // 处理 /config 相关页面
    if (url.pathname.startsWith("/config")) {
      if (url.pathname === "/config/login") {
        if (request.method === "GET") {
          return loginPage();
        } else if (request.method === "POST") {
          return handleLogin(request, env);
        }
      }
      // 对其他 /config 路径先检查登录
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
    } else if (url.pathname.startsWith("/v1/chat/completions")) {
      return handleChatCompletions(request, env);
    }
    return new Response("Not Found", { status: 404 });
  }
};
