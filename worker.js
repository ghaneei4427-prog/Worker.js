// ============================================================
//  FTT Panel v2 — WireGuard/proxy user management panel
//  Runs on Cloudflare Workers + D1
//  Features: stats dashboard, search/filter/sort, bulk actions,
//  CSV export, multi-admin roles, activity log, light/dark theme
// ============================================================

function uuidv4() {
	return crypto.randomUUID();
}

function jsonResponse(data, status = 200) {
	return new Response(JSON.stringify(data), {
		status,
		headers: { "Content-Type": "application/json; charset=utf-8" },
	});
}

async function readJson(request) {
	try {
		const body = await request.json();
		return body && typeof body === "object" ? body : {};
	} catch (e) {
		return {};
	}
}

// ---------------- crypto helpers ----------------

async function sign(secret, message) {
	const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
	return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function sha256Hex(text) {
	const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
	return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// token payload = username:role:expiry, signed with the super-admin password as server secret
async function makeToken(env, username, role) {
	const expiry = Date.now() + 1000 * 60 * 60 * 12; // 12h session
	const payload = `${username}:${role}:${expiry}`;
	const sig = await sign(env.ADMIN_PASSWORD, payload);
	return btoa(`${payload}:${sig}`);
}

async function verifyToken(env, token) {
	try {
		const decoded = atob(token);
		const parts = decoded.split(":");
		if (parts.length !== 4) return null;
		const [username, role, expiry, sig] = parts;
		if (Date.now() > parseInt(expiry)) return null;
		const expectedSig = await sign(env.ADMIN_PASSWORD, `${username}:${role}:${expiry}`);
		if (sig !== expectedSig) return null;
		return { username, role };
	} catch (e) {
		return null;
	}
}

function getBearerToken(request) {
	const auth = request.headers.get("Authorization") || "";
	if (auth.startsWith("Bearer ")) return auth.slice(7);
	return null;
}

async function getSession(request, env) {
	const token = getBearerToken(request);
	if (!token) return null;
	return await verifyToken(env, token);
}

async function logActivity(env, adminUsername, action, target, details) {
	try {
		await env.DB.prepare("INSERT INTO activity_log (admin_username, action, target, details, created_at) VALUES (?, ?, ?, ?, ?)")
			.bind(adminUsername, action, target || null, details || null, Date.now())
			.run();
	} catch (e) {}
}

// ---------------- auth ----------------

async function handleLogin(request, env) {
	const body = await readJson(request);
	const username = (body.username || "").trim();
	const password = body.password || "";

	if (username === env.ADMIN_USERNAME && password === env.ADMIN_PASSWORD) {
		const token = await makeToken(env, username, "super");
		return jsonResponse({ success: true, token, role: "super", panel_name: env.PANEL_NAME || "FTT Panel" });
	}

	const admin = await env.DB.prepare("SELECT * FROM admins WHERE username = ?").bind(username).first();
	if (admin) {
		const hash = await sha256Hex(password);
		if (hash === admin.password_hash) {
			const token = await makeToken(env, username, admin.role);
			return jsonResponse({ success: true, token, role: admin.role, panel_name: env.PANEL_NAME || "FTT Panel" });
		}
	}

	return jsonResponse({ success: false, error: "نام کاربری یا رمز عبور اشتباه است" }, 401);
}

// ---------------- users ----------------

async function handleListUsers(request, env, url) {
	const search = (url.searchParams.get("search") || "").trim();
	const status = url.searchParams.get("status") || "all"; // all | active | inactive | expiring
	const sort = url.searchParams.get("sort") || "id_desc";

	let query = "SELECT * FROM users WHERE 1=1";
	const params = [];
	if (search) {
		query += " AND username LIKE ?";
		params.push(`%${search}%`);
	}
	if (status === "active") query += " AND is_active = 1";
	if (status === "inactive") query += " AND is_active = 0";

	const sortMap = {
		id_desc: "id DESC",
		id_asc: "id ASC",
		username_asc: "username ASC",
		used_desc: "used_gb DESC",
		created_desc: "created_at DESC",
	};
	query += " ORDER BY " + (sortMap[sort] || "id DESC");

	const stmt = params.length ? env.DB.prepare(query).bind(...params) : env.DB.prepare(query);
	const { results } = await stmt.all();
	let users = results || [];

	if (status === "expiring") {
		const now = Date.now();
		users = users.filter((u) => {
			if (!u.expiry_days) return false;
			const remain = Math.ceil((u.created_at + u.expiry_days * 86400000 - now) / 86400000);
			return remain >= 0 && remain <= 3;
		});
	}

	return jsonResponse({ success: true, users });
}

async function handleStats(request, env) {
	const { results } = await env.DB.prepare("SELECT is_active, used_gb, limit_gb, expiry_days, created_at FROM users").all();
	const users = results || [];
	const now = Date.now();
	let active = 0,
		inactive = 0,
		expiringSoon = 0,
		totalUsed = 0;
	users.forEach((u) => {
		if (u.is_active) active++;
		else inactive++;
		totalUsed += u.used_gb || 0;
		if (u.expiry_days) {
			const remain = Math.ceil((u.created_at + u.expiry_days * 86400000 - now) / 86400000);
			if (remain >= 0 && remain <= 3) expiringSoon++;
		}
	});
	return jsonResponse({
		success: true,
		total_users: users.length,
		active_users: active,
		inactive_users: inactive,
		expiring_soon: expiringSoon,
		total_used_gb: Math.round(totalUsed * 100) / 100,
	});
}

async function handleCreateUser(request, env, session) {
	const body = await readJson(request);
	const username = (body.username || "").trim();
	if (!username) return jsonResponse({ success: false, error: "نام کاربری الزامی است" }, 400);

	const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
	if (existing) return jsonResponse({ success: false, error: "این نام کاربری قبلاً ثبت شده" }, 409);

	const uuid = uuidv4();
	const limitGb = body.limit_gb ? parseFloat(body.limit_gb) : null;
	const expiryDays = body.expiry_days ? parseInt(body.expiry_days) : null;
	const note = body.note || "";
	const now = Date.now();

	await env.DB.prepare(
		"INSERT INTO users (username, uuid, limit_gb, used_gb, expiry_days, created_at, is_active, note) VALUES (?, ?, ?, 0, ?, ?, 1, ?)"
	).bind(username, uuid, limitGb, expiryDays, now, note).run();

	await logActivity(env, session.username, "create_user", username, "");
	return jsonResponse({ success: true, message: "کاربر ساخته شد" });
}

async function handleUpdateUser(request, env, id, session) {
	const body = await readJson(request);
	const user = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(id).first();
	if (!user) return jsonResponse({ success: false, error: "کاربر پیدا نشد" }, 404);

	const limitGb = body.limit_gb !== undefined ? (body.limit_gb === "" ? null : parseFloat(body.limit_gb)) : user.limit_gb;
	const expiryDays = body.expiry_days !== undefined ? (body.expiry_days === "" ? null : parseInt(body.expiry_days)) : user.expiry_days;
	const isActive = body.is_active !== undefined ? (body.is_active ? 1 : 0) : user.is_active;
	const note = body.note !== undefined ? body.note : user.note;
	const usedGb = body.reset_usage ? 0 : user.used_gb;

	await env.DB.prepare(
		"UPDATE users SET limit_gb = ?, expiry_days = ?, is_active = ?, note = ?, used_gb = ? WHERE id = ?"
	).bind(limitGb, expiryDays, isActive, note, usedGb, id).run();

	const action = body.reset_usage ? "reset_usage" : body.is_active !== undefined ? (isActive ? "activate_user" : "deactivate_user") : "update_user";
	await logActivity(env, session.username, action, user.username, "");
	return jsonResponse({ success: true, message: "بروزرسانی شد" });
}

async function handleDeleteUser(request, env, id, session) {
	const user = await env.DB.prepare("SELECT username FROM users WHERE id = ?").bind(id).first();
	await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(id).run();
	await logActivity(env, session.username, "delete_user", user ? user.username : `#${id}`, "");
	return jsonResponse({ success: true, message: "کاربر حذف شد" });
}

async function handleBulkAction(request, env, session) {
	const body = await readJson(request);
	const ids = Array.isArray(body.ids) ? body.ids : [];
	const action = body.action;
	if (!ids.length || !action) return jsonResponse({ success: false, error: "درخواست نامعتبر" }, 400);

	const placeholders = ids.map(() => "?").join(",");
	if (action === "delete") {
		await env.DB.prepare(`DELETE FROM users WHERE id IN (${placeholders})`).bind(...ids).run();
	} else if (action === "activate") {
		await env.DB.prepare(`UPDATE users SET is_active = 1 WHERE id IN (${placeholders})`).bind(...ids).run();
	} else if (action === "deactivate") {
		await env.DB.prepare(`UPDATE users SET is_active = 0 WHERE id IN (${placeholders})`).bind(...ids).run();
	} else if (action === "reset") {
		await env.DB.prepare(`UPDATE users SET used_gb = 0 WHERE id IN (${placeholders})`).bind(...ids).run();
	} else {
		return jsonResponse({ success: false, error: "عملیات نامعتبر" }, 400);
	}

	await logActivity(env, session.username, "bulk_" + action, `${ids.length} کاربر`, "");
	return jsonResponse({ success: true, message: "عملیات گروهی انجام شد" });
}

async function handleExportCsv(request, env) {
	const { results } = await env.DB.prepare("SELECT username, limit_gb, used_gb, expiry_days, created_at, is_active, note FROM users ORDER BY id DESC").all();
	const rows = results || [];
	const header = "username,limit_gb,used_gb,expiry_days,created_at,is_active,note";
	const lines = rows.map((r) =>
		[r.username, r.limit_gb ?? "", r.used_gb ?? 0, r.expiry_days ?? "", new Date(r.created_at).toISOString(), r.is_active, (r.note || "").replace(/,/g, ";")].join(",")
	);
	const csv = [header, ...lines].join("\n");
	return new Response(csv, {
		headers: {
			"Content-Type": "text/csv; charset=utf-8",
			"Content-Disposition": `attachment; filename="ftt-users-${Date.now()}.csv"`,
		},
	});
}

// ---------------- admins (operators) ----------------

async function handleListAdmins(request, env) {
	const { results } = await env.DB.prepare("SELECT id, username, role, created_at FROM admins ORDER BY id DESC").all();
	return jsonResponse({ success: true, admins: results || [] });
}

async function handleCreateAdmin(request, env, session) {
	const body = await readJson(request);
	const username = (body.username || "").trim();
	const password = body.password || "";
	const role = body.role === "admin" ? "admin" : "viewer";
	if (!username || !password) return jsonResponse({ success: false, error: "نام کاربری و رمز الزامی است" }, 400);

	const existing = await env.DB.prepare("SELECT id FROM admins WHERE username = ?").bind(username).first();
	if (existing) return jsonResponse({ success: false, error: "این نام کاربری قبلاً وجود دارد" }, 409);

	const hash = await sha256Hex(password);
	await env.DB.prepare("INSERT INTO admins (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)")
		.bind(username, hash, role, Date.now())
		.run();

	await logActivity(env, session.username, "create_admin", username, role);
	return jsonResponse({ success: true, message: "اپراتور اضافه شد" });
}

async function handleDeleteAdmin(request, env, id, session) {
	const admin = await env.DB.prepare("SELECT username FROM admins WHERE id = ?").bind(id).first();
	await env.DB.prepare("DELETE FROM admins WHERE id = ?").bind(id).run();
	await logActivity(env, session.username, "delete_admin", admin ? admin.username : `#${id}`, "");
	return jsonResponse({ success: true, message: "اپراتور حذف شد" });
}

// ---------------- activity log ----------------

async function handleLogs(request, env) {
	const { results } = await env.DB.prepare("SELECT * FROM activity_log ORDER BY id DESC LIMIT 100").all();
	return jsonResponse({ success: true, logs: results || [] });
}

// ---------------- public status ----------------

async function handlePublicStatus(request, env, uuid) {
	const user = await env.DB.prepare("SELECT username, limit_gb, used_gb, expiry_days, created_at, is_active FROM users WHERE uuid = ?").bind(uuid).first();
	if (!user) return jsonResponse({ success: false, error: "کاربر پیدا نشد" }, 404);

	let daysRemaining = null;
	let isExpired = false;
	if (user.expiry_days) {
		const expiryDate = user.created_at + user.expiry_days * 86400000;
		daysRemaining = Math.max(0, Math.ceil((expiryDate - Date.now()) / 86400000));
		isExpired = Date.now() > expiryDate;
	}
	const isVolumeExpired = user.limit_gb ? user.used_gb >= user.limit_gb : false;

	return jsonResponse({
		success: true,
		username: user.username,
		used_gb: user.used_gb,
		limit_gb: user.limit_gb,
		days_remaining: daysRemaining,
		is_active: !!user.is_active && !isExpired && !isVolumeExpired,
	});
}

// ---------------- Router ----------------

const WRITE_ACTIONS = new Set(["POST", "PATCH", "DELETE", "PUT"]);

export default {
	async fetch(request, env, ctx) {
		const url = new URL(request.url);
		const path = url.pathname;

		if (path.startsWith("/api/status/")) {
			return handlePublicStatus(request, env, path.split("/api/status/")[1]);
		}
		if (path.startsWith("/status/")) {
			return new Response(renderStatusPage(env), { headers: { "Content-Type": "text/html; charset=utf-8" } });
		}

		if (path === "/api/login" && request.method === "POST") {
			return handleLogin(request, env);
		}

		if (path.startsWith("/api/")) {
			const session = await getSession(request, env);
			if (!session) return jsonResponse({ success: false, error: "دسترسی غیرمجاز" }, 401);

			// viewers may only GET
			if (session.role === "viewer" && WRITE_ACTIONS.has(request.method)) {
				return jsonResponse({ success: false, error: "دسترسی فقط-خواندنی است" }, 403);
			}

			if (path === "/api/stats" && request.method === "GET") return handleStats(request, env);
			if (path === "/api/users" && request.method === "GET") return handleListUsers(request, env, url);
			if (path === "/api/users" && request.method === "POST") return handleCreateUser(request, env, session);
			if (path === "/api/users/export" && request.method === "GET") return handleExportCsv(request, env);
			if (path === "/api/users/bulk" && request.method === "POST") return handleBulkAction(request, env, session);

			const matchUser = path.match(/^\/api\/users\/(\d+)$/);
			if (matchUser && request.method === "PATCH") return handleUpdateUser(request, env, matchUser[1], session);
			if (matchUser && request.method === "DELETE") return handleDeleteUser(request, env, matchUser[1], session);

			// admin/operator management — super only
			if (path === "/api/admins") {
				if (session.role !== "super") return jsonResponse({ success: false, error: "فقط ادمین اصلی دسترسی دارد" }, 403);
				if (request.method === "GET") return handleListAdmins(request, env);
				if (request.method === "POST") return handleCreateAdmin(request, env, session);
			}
			const matchAdmin = path.match(/^\/api\/admins\/(\d+)$/);
			if (matchAdmin && request.method === "DELETE") {
				if (session.role !== "super") return jsonResponse({ success: false, error: "فقط ادمین اصلی دسترسی دارد" }, 403);
				return handleDeleteAdmin(request, env, matchAdmin[1], session);
			}

			if (path === "/api/logs" && request.method === "GET") return handleLogs(request, env);

			return jsonResponse({ success: false, error: "مسیر پیدا نشد" }, 404);
		}

		if (path === "/" || path === "/admin") {
			return new Response(renderAdminPage(env), { headers: { "Content-Type": "text/html; charset=utf-8" } });
		}

		return new Response("Not found", { status: 404 });
	},
};

// ---------------- HTML views ----------------

function renderAdminPage(env) {
	const panelName = env.PANEL_NAME || "FTT Panel";
	return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${panelName}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/3.4.1/tailwind.min.css"></script>
<style>
  body.dark { background:#0f172a; color:#f1f5f9; }
  body.light { background:#f1f5f9; color:#0f172a; }
  body.dark .card { background:rgba(30,41,59,.6); border-color:#334155; }
  body.light .card { background:rgba(255,255,255,.9); border-color:#e2e8f0; }
  body.dark input, body.dark select { background:#0f172a; border-color:#334155; color:#f1f5f9; }
  body.light input, body.light select { background:#fff; border-color:#e2e8f0; color:#0f172a; }
  body.dark table thead { background:rgba(15,23,42,.6); color:#94a3b8; }
  body.light table thead { background:#f8fafc; color:#64748b; }
  body.dark tr { border-color:rgba(51,65,85,.5); }
  body.light tr { border-color:rgba(226,232,240,.8); }
  ::-webkit-scrollbar { width: 8px; }
  ::-webkit-scrollbar-thumb { background: #64748b; border-radius: 4px; }
</style>
</head>
<body class="dark min-h-screen font-sans transition-colors">

<div id="login-screen" class="min-h-screen flex items-center justify-center p-4">
  <div class="card backdrop-blur border rounded-2xl p-8 w-full max-w-sm shadow-xl">
    <h1 class="text-2xl font-bold text-center mb-1 bg-gradient-to-l from-cyan-400 to-blue-500 bg-clip-text text-transparent">${panelName}</h1>
    <p class="text-center opacity-60 text-sm mb-6">ورود مدیریت</p>
    <input id="login-user" placeholder="نام کاربری" class="w-full mb-3 px-4 py-2.5 rounded-lg border focus:border-cyan-500 outline-none text-sm">
    <input id="login-pass" type="password" placeholder="رمز عبور" class="w-full mb-4 px-4 py-2.5 rounded-lg border focus:border-cyan-500 outline-none text-sm">
    <button onclick="doLogin()" class="w-full py-2.5 rounded-lg bg-gradient-to-l from-cyan-500 to-blue-600 font-bold text-white hover:opacity-90 transition">ورود</button>
    <p id="login-error" class="text-red-400 text-xs text-center mt-3 hidden"></p>
  </div>
</div>

<div id="dashboard" class="hidden max-w-6xl mx-auto p-4 md:p-8">
  <div class="flex items-center justify-between mb-6">
    <h1 class="text-xl font-bold bg-gradient-to-l from-cyan-400 to-blue-500 bg-clip-text text-transparent">${panelName}</h1>
    <div class="flex items-center gap-3">
      <button onclick="toggleTheme()" id="theme-btn" class="text-xs opacity-70 hover:opacity-100 transition px-2 py-1">🌙</button>
      <span id="role-badge" class="text-xs opacity-60"></span>
      <button onclick="logout()" class="text-xs opacity-70 hover:text-red-400 transition">خروج</button>
    </div>
  </div>

  <!-- Stats cards -->
  <div id="stats-cards" class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6"></div>

  <!-- Add user -->
  <div class="card border rounded-2xl p-5 mb-6" id="add-user-box">
    <h2 class="font-bold mb-4 text-sm opacity-80">افزودن کاربر جدید</h2>
    <div class="grid grid-cols-2 md:grid-cols-5 gap-3">
      <input id="new-username" placeholder="نام کاربری" class="px-3 py-2 rounded-lg border text-sm outline-none focus:border-cyan-500">
      <input id="new-limit" type="number" placeholder="حجم (GB)" class="px-3 py-2 rounded-lg border text-sm outline-none focus:border-cyan-500">
      <input id="new-expiry" type="number" placeholder="روز اعتبار" class="px-3 py-2 rounded-lg border text-sm outline-none focus:border-cyan-500">
      <input id="new-note" placeholder="یادداشت" class="px-3 py-2 rounded-lg border text-sm outline-none focus:border-cyan-500">
      <button onclick="createUser()" class="px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-sm transition">افزودن</button>
    </div>
  </div>

  <!-- Search / filter / sort / export -->
  <div class="flex flex-wrap gap-3 mb-4 items-center">
    <input id="search-box" placeholder="جست‌وجوی کاربر..." oninput="debouncedLoad()" class="px-3 py-2 rounded-lg border text-sm outline-none focus:border-cyan-500 flex-1 min-w-[160px]">
    <select id="status-filter" onchange="loadUsers()" class="px-3 py-2 rounded-lg border text-sm outline-none">
      <option value="all">همه</option>
      <option value="active">فعال</option>
      <option value="inactive">غیرفعال</option>
      <option value="expiring">نزدیک انقضا</option>
    </select>
    <select id="sort-select" onchange="loadUsers()" class="px-3 py-2 rounded-lg border text-sm outline-none">
      <option value="id_desc">جدیدترین</option>
      <option value="id_asc">قدیمی‌ترین</option>
      <option value="username_asc">حروف الفبا</option>
      <option value="used_desc">بیشترین مصرف</option>
    </select>
    <button onclick="exportCsv()" class="px-3 py-2 rounded-lg border text-sm hover:border-cyan-500 transition">📥 خروجی CSV</button>
  </div>

  <!-- Bulk action bar -->
  <div id="bulk-bar" class="hidden flex items-center gap-2 mb-3 text-sm">
    <span id="bulk-count" class="opacity-70"></span>
    <button onclick="bulkAction('activate')" class="px-2 py-1 rounded border hover:border-cyan-500">فعال کردن</button>
    <button onclick="bulkAction('deactivate')" class="px-2 py-1 rounded border hover:border-cyan-500">غیرفعال کردن</button>
    <button onclick="bulkAction('reset')" class="px-2 py-1 rounded border hover:border-cyan-500">ریست حجم</button>
    <button onclick="bulkAction('delete')" class="px-2 py-1 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10">حذف</button>
  </div>

  <div class="card border rounded-2xl overflow-x-auto mb-8">
    <table class="w-full text-sm">
      <thead>
        <tr>
          <th class="p-3"><input type="checkbox" id="select-all" onchange="toggleSelectAll(this)"></th>
          <th class="p-3 text-right">کاربر</th>
          <th class="p-3 text-right">مصرف</th>
          <th class="p-3 text-right">انقضا</th>
          <th class="p-3 text-right">وضعیت</th>
          <th class="p-3 text-right">عملیات</th>
        </tr>
      </thead>
      <tbody id="users-body"></tbody>
    </table>
  </div>

  <!-- Operators (super only) -->
  <div id="admins-section" class="hidden mb-8">
    <h2 class="font-bold mb-3 text-sm opacity-80">اپراتورها / سطح دسترسی</h2>
    <div class="card border rounded-2xl p-5 mb-3">
      <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
        <input id="admin-username" placeholder="نام کاربری اپراتور" class="px-3 py-2 rounded-lg border text-sm outline-none">
        <input id="admin-password" type="password" placeholder="رمز عبور" class="px-3 py-2 rounded-lg border text-sm outline-none">
        <select id="admin-role" class="px-3 py-2 rounded-lg border text-sm outline-none">
          <option value="viewer">فقط مشاهده (viewer)</option>
          <option value="admin">دسترسی کامل (admin)</option>
        </select>
        <button onclick="createAdmin()" class="px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-sm transition">افزودن اپراتور</button>
      </div>
    </div>
    <div class="card border rounded-2xl overflow-hidden">
      <table class="w-full text-sm">
        <thead><tr><th class="p-3 text-right">نام کاربری</th><th class="p-3 text-right">نقش</th><th class="p-3 text-right">عملیات</th></tr></thead>
        <tbody id="admins-body"></tbody>
      </table>
    </div>
  </div>

  <!-- Activity log -->
  <div>
    <h2 class="font-bold mb-3 text-sm opacity-80">لاگ فعالیت (۱۰۰ مورد اخیر)</h2>
    <div class="card border rounded-2xl overflow-hidden max-h-80 overflow-y-auto">
      <table class="w-full text-xs">
        <thead><tr><th class="p-2 text-right">زمان</th><th class="p-2 text-right">اپراتور</th><th class="p-2 text-right">عملیات</th><th class="p-2 text-right">هدف</th></tr></thead>
        <tbody id="logs-body"></tbody>
      </table>
    </div>
  </div>
</div>

<script>
let token = localStorage.getItem('ftt_token') || null;
let currentRole = localStorage.getItem('ftt_role') || null;
let debounceTimer = null;

// ---- theme ----
function applyTheme(theme) {
  document.body.classList.remove('dark','light');
  document.body.classList.add(theme);
  document.getElementById('theme-btn').innerText = theme === 'dark' ? '🌙' : '☀️';
  localStorage.setItem('ftt_theme', theme);
}
function toggleTheme() {
  const current = document.body.classList.contains('dark') ? 'dark' : 'light';
  applyTheme(current === 'dark' ? 'light' : 'dark');
}
applyTheme(localStorage.getItem('ftt_theme') || 'dark');

function showError(msg) {
  const el = document.getElementById('login-error');
  el.innerText = msg;
  el.classList.remove('hidden');
}

async function doLogin() {
  const username = document.getElementById('login-user').value.trim();
  const password = document.getElementById('login-pass').value;
  try {
    const res = await fetch('/api/login', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({username, password}) });
    const data = await res.json();
    if (data.success) {
      token = data.token;
      currentRole = data.role;
      localStorage.setItem('ftt_token', token);
      localStorage.setItem('ftt_role', currentRole);
      showDashboard();
    } else {
      showError(data.error || 'خطا در ورود');
    }
  } catch (e) {
    showError('خطای اتصال به سرور');
  }
}

function logout() {
  localStorage.removeItem('ftt_token');
  localStorage.removeItem('ftt_role');
  token = null;
  document.getElementById('dashboard').classList.add('hidden');
  document.getElementById('login-screen').classList.remove('hidden');
}

function authHeaders(extra) {
  return Object.assign({ 'Authorization': 'Bearer ' + token }, extra || {});
}

async function showDashboard() {
  document.getElementById('login-screen').classList.add('hidden');
  document.getElementById('dashboard').classList.remove('hidden');
  document.getElementById('role-badge').innerText = currentRole === 'super' ? '👑 ادمین اصلی' : currentRole === 'admin' ? '🛠️ اپراتور' : '👁️ فقط مشاهده';
  if (currentRole === 'viewer') document.getElementById('add-user-box').classList.add('hidden');
  if (currentRole === 'super') document.getElementById('admins-section').classList.remove('hidden');
  await Promise.all([loadStats(), loadUsers(), loadLogs()]);
  if (currentRole === 'super') loadAdmins();
}

async function loadStats() {
  const res = await fetch('/api/stats', { headers: authHeaders() });
  if (res.status === 401) return logout();
  const d = await res.json();
  const cards = [
    { label: 'کل کاربرها', value: d.total_users, color: 'text-cyan-400' },
    { label: 'فعال', value: d.active_users, color: 'text-green-400' },
    { label: 'نزدیک انقضا', value: d.expiring_soon, color: 'text-yellow-400' },
    { label: 'مجموع مصرف (GB)', value: d.total_used_gb, color: 'text-blue-400' },
  ];
  document.getElementById('stats-cards').innerHTML = cards.map(c =>
    \`<div class="card border rounded-xl p-4 text-center"><p class="text-2xl font-bold \${c.color}">\${c.value}</p><p class="text-xs opacity-60 mt-1">\${c.label}</p></div>\`
  ).join('');
}

function debouncedLoad() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(loadUsers, 350);
}

async function loadUsers() {
  const search = document.getElementById('search-box').value.trim();
  const status = document.getElementById('status-filter').value;
  const sort = document.getElementById('sort-select').value;
  const qs = new URLSearchParams({ search, status, sort });
  const res = await fetch('/api/users?' + qs.toString(), { headers: authHeaders() });
  if (res.status === 401) return logout();
  const data = await res.json();
  const tbody = document.getElementById('users-body');
  tbody.innerHTML = '';
  (data.users || []).forEach(u => {
    const usedTxt = (u.used_gb || 0).toFixed(2) + ' / ' + (u.limit_gb ? u.limit_gb + ' GB' : '∞');
    let expiryTxt = 'نامحدود';
    if (u.expiry_days) {
      const remain = Math.max(0, Math.ceil((u.created_at + u.expiry_days*86400000 - Date.now())/86400000));
      expiryTxt = remain + ' روز';
    }
    const statusBadge = u.is_active
      ? '<span class="px-2 py-1 rounded-full bg-green-500/10 text-green-400 text-xs border border-green-500/30">فعال</span>'
      : '<span class="px-2 py-1 rounded-full bg-red-500/10 text-red-400 text-xs border border-red-500/30">غیرفعال</span>';
    const disabled = currentRole === 'viewer' ? 'disabled style="opacity:.4;cursor:not-allowed"' : '';
    const row = document.createElement('tr');
    row.className = 'border-t';
    row.innerHTML = \`
      <td class="p-3"><input type="checkbox" class="row-check" value="\${u.id}" onchange="updateBulkBar()"></td>
      <td class="p-3 font-mono">\${u.username}
        <button onclick="copyStatusLink('\${u.uuid}')" title="کپی لینک وضعیت" class="opacity-50 hover:opacity-100 text-xs">🔗</button>
      </td>
      <td class="p-3">\${usedTxt}</td>
      <td class="p-3">\${expiryTxt}</td>
      <td class="p-3">\${statusBadge}</td>
      <td class="p-3 flex gap-2 flex-wrap">
        <button \${disabled} onclick="toggleActive(\${u.id}, \${u.is_active})" class="text-xs px-2 py-1 rounded border hover:border-cyan-500">\${u.is_active ? 'غیرفعال کن' : 'فعال کن'}</button>
        <button \${disabled} onclick="resetUsage(\${u.id})" class="text-xs px-2 py-1 rounded border hover:border-cyan-500">ریست حجم</button>
        <button \${disabled} onclick="deleteUser(\${u.id})" class="text-xs px-2 py-1 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10">حذف</button>
      </td>\`;
    tbody.appendChild(row);
  });
  updateBulkBar();
}

function copyStatusLink(uuid) {
  const link = location.origin + '/status/' + uuid;
  navigator.clipboard.writeText(link).then(() => alert('لینک کپی شد'));
}

function toggleSelectAll(cb) {
  document.querySelectorAll('.row-check').forEach(c => c.checked = cb.checked);
  updateBulkBar();
}

function getSelectedIds() {
  return Array.from(document.querySelectorAll('.row-check:checked')).map(c => parseInt(c.value));
}

function updateBulkBar() {
  const ids = getSelectedIds();
  const bar = document.getElementById('bulk-bar');
  if (ids.length > 0) {
    bar.classList.remove('hidden');
    document.getElementById('bulk-count').innerText = ids.length + ' مورد انتخاب شده';
  } else {
    bar.classList.add('hidden');
  }
}

async function bulkAction(action) {
  const ids = getSelectedIds();
  if (!ids.length) return;
  if (action === 'delete' && !confirm(ids.length + ' کاربر حذف شوند؟')) return;
  await fetch('/api/users/bulk', { method: 'POST', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify({ ids, action }) });
  loadUsers(); loadStats(); loadLogs();
}

async function exportCsv() {
  const res = await fetch('/api/users/export', { headers: authHeaders() });
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = 'ftt-users.csv'; a.click();
  URL.revokeObjectURL(url);
}

async function createUser() {
  const username = document.getElementById('new-username').value.trim();
  const limit_gb = document.getElementById('new-limit').value;
  const expiry_days = document.getElementById('new-expiry').value;
  const note = document.getElementById('new-note').value;
  if (!username) return alert('نام کاربری را وارد کنید');
  const res = await fetch('/api/users', { method: 'POST', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify({ username, limit_gb, expiry_days, note }) });
  const data = await res.json();
  if (!data.success) return alert(data.error);
  document.getElementById('new-username').value = '';
  document.getElementById('new-limit').value = '';
  document.getElementById('new-expiry').value = '';
  document.getElementById('new-note').value = '';
  loadUsers(); loadStats(); loadLogs();
}

async function toggleActive(id, current) {
  await fetch('/api/users/' + id, { method: 'PATCH', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify({ is_active: current ? 0 : 1 }) });
  loadUsers(); loadStats(); loadLogs();
}

async function resetUsage(id) {
  await fetch('/api/users/' + id, { method: 'PATCH', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify({ reset_usage: true }) });
  loadUsers(); loadStats(); loadLogs();
}

async function deleteUser(id) {
  if (!confirm('حذف این کاربر مطمئنی؟')) return;
  await fetch('/api/users/' + id, { method: 'DELETE', headers: authHeaders() });
  loadUsers(); loadStats(); loadLogs();
}

// ---- admins ----
async function loadAdmins() {
  const res = await fetch('/api/admins', { headers: authHeaders() });
  const data = await res.json();
  const tbody = document.getElementById('admins-body');
  tbody.innerHTML = '';
  (data.admins || []).forEach(a => {
    const row = document.createElement('tr');
    row.className = 'border-t';
    row.innerHTML = \`<td class="p-3 font-mono">\${a.username}</td><td class="p-3">\${a.role === 'admin' ? 'دسترسی کامل' : 'فقط مشاهده'}</td>
      <td class="p-3"><button onclick="deleteAdmin(\${a.id})" class="text-xs px-2 py-1 rounded border border-red-500/40 text-red-400 hover:bg-red-500/10">حذف</button></td>\`;
    tbody.appendChild(row);
  });
}

async function createAdmin() {
  const username = document.getElementById('admin-username').value.trim();
  const password = document.getElementById('admin-password').value;
  const role = document.getElementById('admin-role').value;
  if (!username || !password) return alert('نام کاربری و رمز را وارد کنید');
  const res = await fetch('/api/admins', { method: 'POST', headers: authHeaders({'Content-Type':'application/json'}), body: JSON.stringify({ username, password, role }) });
  const data = await res.json();
  if (!data.success) return alert(data.error);
  document.getElementById('admin-username').value = '';
  document.getElementById('admin-password').value = '';
  loadAdmins(); loadLogs();
}

async function deleteAdmin(id) {
  if (!confirm('این اپراتور حذف شود؟')) return;
  await fetch('/api/admins/' + id, { method: 'DELETE', headers: authHeaders() });
  loadAdmins(); loadLogs();
}

// ---- logs ----
async function loadLogs() {
  const res = await fetch('/api/logs', { headers: authHeaders() });
  const data = await res.json();
  const tbody = document.getElementById('logs-body');
  tbody.innerHTML = '';
  (data.logs || []).forEach(l => {
    const row = document.createElement('tr');
    row.className = 'border-t';
    const time = new Date(l.created_at).toLocaleString('fa-IR');
    row.innerHTML = \`<td class="p-2 opacity-60">\${time}</td><td class="p-2">\${l.admin_username}</td><td class="p-2">\${l.action}</td><td class="p-2">\${l.target || '-'}</td>\`;
    tbody.appendChild(row);
  });
}

if (token) showDashboard();
</script>
</body>
</html>`;
}

function renderStatusPage(env) {
	const panelName = env.PANEL_NAME || "FTT Panel";
	return `<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>وضعیت اشتراک — ${panelName}</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/3.4.1/tailwind.min.css"></script>
</head>
<body class="min-h-screen bg-slate-900 text-slate-100 flex items-center justify-center p-4">
  <div id="card" class="bg-slate-800/60 border border-slate-700 rounded-2xl p-6 w-full max-w-sm text-center">
    <p class="text-slate-400 text-sm">در حال بارگذاری...</p>
  </div>
<script>
  const uuid = location.pathname.split('/status/')[1];
  fetch('/api/status/' + uuid).then(r => r.json()).then(data => {
    const card = document.getElementById('card');
    if (!data.success) { card.innerHTML = '<p class="text-red-400">کاربر پیدا نشد</p>'; return; }
    card.innerHTML = \`
      <h1 class="text-lg font-bold mb-4">\${data.username}</h1>
      <p class="text-sm text-slate-400 mb-1">مصرف حجم</p>
      <p class="text-2xl font-bold mb-4">\${data.used_gb.toFixed(2)} / \${data.limit_gb ? data.limit_gb + ' GB' : '∞'}</p>
      <p class="text-sm text-slate-400 mb-1">روزهای باقیمانده</p>
      <p class="text-2xl font-bold mb-4">\${data.days_remaining === null ? 'نامحدود' : data.days_remaining + ' روز'}</p>
      <span class="px-3 py-1 rounded-full text-sm \${data.is_active ? 'bg-green-500/10 text-green-400 border border-green-500/30' : 'bg-red-500/10 text-red-400 border border-red-500/30'}">\${data.is_active ? 'فعال' : 'غیرفعال'}</span>
    \`;
  });
</script>
</body>
</html>`;
}
