/**
 * EdgeStash - Cloudflare-based Cloud Drive
 * 
 * A complete cloud storage solution built on Cloudflare Worker, R2, and KV.
 * 
 * Environment Variables (set in Cloudflare Dashboard):
 * - ADMIN_PASSWORD: Administrator password for login
 * 
 * Bindings (set in Cloudflare Dashboard):
 * - R2_BUCKET: R2 bucket binding for file storage
 * - KV_STORE: KV namespace binding for metadata storage
 */

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Generate a random string for IDs and tokens
 */
function generateId(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  for (let i = 0; i < length; i++) {
    result += chars[randomValues[i] % chars.length];
  }
  return result;
}

/**
 * Hash a password using SHA-256
 */
async function hashPassword(password) {
  const encoder = new TextEncoder();
  const data = encoder.encode(password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Create a JWT token
 */
async function createJWT(payload, secret) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    encoder.encode(`${encodedHeader}.${encodedPayload}`)
  );
  
  const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature)))
    .replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
  
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

/**
 * Verify a JWT token
 */
async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    
    const [encodedHeader, encodedPayload, encodedSignature] = parts;
    
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );
    
    const signatureData = Uint8Array.from(atob(encodedSignature.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
    
    const valid = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureData,
      encoder.encode(`${encodedHeader}.${encodedPayload}`)
    );
    
    if (!valid) return null;
    
    const payload = JSON.parse(atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/')));
    
    // Check expiration
    if (payload.exp && Date.now() > payload.exp) return null;
    
    return payload;
  } catch (e) {
    return null;
  }
}

/**
 * Get expiration timestamp based on duration string
 */
function getExpirationTime(expiresIn) {
  const now = Date.now();
  switch (expiresIn) {
    case '1h': return now + 60 * 60 * 1000;
    case '1d': return now + 24 * 60 * 60 * 1000;
    case '1m': return now + 30 * 24 * 60 * 60 * 1000;
    case 'permanent': return null;
    default: return now + 24 * 60 * 60 * 1000;
  }
}

/**
 * Format file size for display
 */
function formatFileSize(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Get MIME type from file extension
 */
function getMimeType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  const mimeTypes = {
    'html': 'text/html',
    'css': 'text/css',
    'js': 'application/javascript',
    'json': 'application/json',
    'png': 'image/png',
    'jpg': 'image/jpeg',
    'jpeg': 'image/jpeg',
    'gif': 'image/gif',
    'svg': 'image/svg+xml',
    'webp': 'image/webp',
    'ico': 'image/x-icon',
    'pdf': 'application/pdf',
    'zip': 'application/zip',
    'txt': 'text/plain',
    'md': 'text/markdown',
    'mp3': 'audio/mpeg',
    'mp4': 'video/mp4',
    'webm': 'video/webm',
    'doc': 'application/msword',
    'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'xls': 'application/vnd.ms-excel',
    'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'ppt': 'application/vnd.ms-powerpoint',
    'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  };
  return mimeTypes[ext] || 'application/octet-stream';
}

/**
 * Check if file is previewable
 */
function getPreviewType(filename) {
  const ext = filename.split('.').pop().toLowerCase();
  
  // Image files
  if (['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'ico', 'bmp'].includes(ext)) {
    return 'image';
  }
  
  // PDF files
  if (ext === 'pdf') {
    return 'pdf';
  }
  
  // Text/code files
  if (['txt', 'md', 'json', 'js', 'ts', 'css', 'html', 'xml', 'yaml', 'yml', 'ini', 'conf', 'sh', 'bash', 'py', 'java', 'c', 'cpp', 'h', 'hpp', 'go', 'rs', 'sql', 'log'].includes(ext)) {
    return 'text';
  }
  
  // Word documents (use Mammoth.js)
  if (ext === 'docx') {
    return 'word';
  }
  
  // Video files
  if (['mp4', 'webm', 'ogg'].includes(ext)) {
    return 'video';
  }
  
  // Audio files
  if (['mp3', 'wav', 'ogg', 'flac', 'm4a'].includes(ext)) {
    return 'audio';
  }
  
  return null;
}

/**
 * Parse cookies from request
 */
function parseCookies(request) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const cookies = {};
  cookieHeader.split(';').forEach(cookie => {
    const [name, value] = cookie.trim().split('=');
    if (name && value) {
      cookies[name] = decodeURIComponent(value);
    }
  });
  return cookies;
}

/**
 * Create JSON response
 */
function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...headers
    }
  });
}

/**
 * Create HTML response
 */
function htmlResponse(html, status = 200, headers = {}) {
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      ...headers
    }
  });
}

// ============================================================================
// AUTHENTICATION HANDLERS
// ============================================================================

async function handleLogin(request, env) {
  try {
    const body = await request.json();
    const { email, password, isAdmin } = body;
    
    if (isAdmin) {
      // Admin login
      if (password === env.ADMIN_PASSWORD) {
        const token = await createJWT(
          { role: 'admin', exp: Date.now() + 24 * 60 * 60 * 1000 },
          env.ADMIN_PASSWORD
        );
        return jsonResponse(
          { success: true, role: 'admin' },
          200,
          { 'Set-Cookie': `token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400` }
        );
      }
      return jsonResponse({ success: false, message: '管理员密码错误' }, 401);
    } else {
      // User login
      if (!email || !password) {
        return jsonResponse({ success: false, message: '请输入邮箱和密码' }, 400);
      }
      
      const userData = await env.KV_STORE.get(`user:${email}`);
      if (!userData) {
        return jsonResponse({ success: false, message: '用户不存在' }, 401);
      }
      
      const user = JSON.parse(userData);
      const passwordHash = await hashPassword(password);
      
      if (user.passwordHash !== passwordHash) {
        return jsonResponse({ success: false, message: '密码错误' }, 401);
      }
      
      const token = await createJWT(
        { email: user.email, role: 'user', exp: Date.now() + 24 * 60 * 60 * 1000 },
        env.ADMIN_PASSWORD
      );
      
      return jsonResponse(
        { success: true, role: 'user', email: user.email },
        200,
        { 'Set-Cookie': `token=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400` }
      );
    }
  } catch (e) {
    return jsonResponse({ success: false, message: '登录失败: ' + e.message }, 500);
  }
}

async function handleLogout() {
  return jsonResponse(
    { success: true },
    200,
    { 'Set-Cookie': 'token=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0' }
  );
}

async function verifyAuth(request, env) {
  const cookies = parseCookies(request);
  const token = cookies.token;
  
  if (!token) return null;
  
  return await verifyJWT(token, env.ADMIN_PASSWORD);
}

async function requireAuth(request, env) {
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return jsonResponse({ success: false, message: '未授权' }, 401);
  }
  return auth;
}

async function requireAdmin(request, env) {
  const auth = await verifyAuth(request, env);
  if (!auth || auth.role !== 'admin') {
    return jsonResponse({ success: false, message: '需要管理员权限' }, 403);
  }
  return auth;
}

// ============================================================================
// FILE MANAGEMENT HANDLERS
// ============================================================================

async function handleListFiles(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    // Normalize path
    let prefix = path || '';
    if (prefix && !prefix.endsWith('/')) prefix += '/';
    if (prefix.startsWith('/')) prefix = prefix.slice(1);
    
    const listed = await env.R2_BUCKET.list({ prefix, delimiter: '/' });
    
    const files = [];
    const folders = [];
    
    // Process folders (common prefixes)
    if (listed.delimitedPrefixes) {
      for (const folderPath of listed.delimitedPrefixes) {
        const name = folderPath.slice(prefix.length, -1);
        if (name) {
          folders.push({ name, path: '/' + folderPath.slice(0, -1) });
        }
      }
    }
    
    // Process files
    if (listed.objects) {
      for (const obj of listed.objects) {
        const name = obj.key.slice(prefix.length);
        if (name && !name.includes('/')) {
          const previewType = getPreviewType(name);
          files.push({
            name,
            path: '/' + obj.key,
            size: obj.size,
            sizeFormatted: formatFileSize(obj.size),
            lastModified: obj.uploaded.toISOString(),
            previewType
          });
        }
      }
    }
    
    return jsonResponse({ success: true, files, folders, currentPath: '/' + prefix.slice(0, -1) || '/' });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取文件列表失败: ' + e.message }, 500);
  }
}

async function handleUploadFile(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const formData = await request.formData();
    const file = formData.get('file');
    
    if (!file) {
      return jsonResponse({ success: false, message: '没有上传文件' }, 400);
    }
    
    // Normalize path
    let filePath = path || '';
    if (filePath.startsWith('/')) filePath = filePath.slice(1);
    if (filePath && !filePath.endsWith('/')) filePath += '/';
    
    const key = filePath + file.name;
    
    await env.R2_BUCKET.put(key, file.stream(), {
      httpMetadata: { contentType: file.type || getMimeType(file.name) }
    });
    
    return jsonResponse({ success: true, message: '文件上传成功', path: '/' + key });
  } catch (e) {
    return jsonResponse({ success: false, message: '文件上传失败: ' + e.message }, 500);
  }
}

async function handleDeleteFile(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    let key = path || '';
    if (key.startsWith('/')) key = key.slice(1);
    
    // Check if it's a folder (has objects with this prefix)
    const listed = await env.R2_BUCKET.list({ prefix: key + '/', limit: 1 });
    
    if (listed.objects && listed.objects.length > 0) {
      // It's a folder, delete all contents recursively
      let cursor;
      do {
        const batch = await env.R2_BUCKET.list({ prefix: key + '/', cursor });
        if (batch.objects && batch.objects.length > 0) {
          await env.R2_BUCKET.delete(batch.objects.map(obj => obj.key));
        }
        cursor = batch.truncated ? batch.cursor : null;
      } while (cursor);
    }
    
    // Try to delete the file itself
    await env.R2_BUCKET.delete(key);
    
    return jsonResponse({ success: true, message: '删除成功' });
  } catch (e) {
    return jsonResponse({ success: false, message: '删除失败: ' + e.message }, 500);
  }
}

async function handleRenameFile(request, env, path) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const body = await request.json();
    const { newName } = body;
    
    if (!newName) {
      return jsonResponse({ success: false, message: '请提供新名称' }, 400);
    }
    
    let oldKey = path || '';
    if (oldKey.startsWith('/')) oldKey = oldKey.slice(1);
    
    const parentPath = oldKey.includes('/') ? oldKey.substring(0, oldKey.lastIndexOf('/') + 1) : '';
    const newKey = parentPath + newName;
    
    // Get the old file
    const oldObject = await env.R2_BUCKET.get(oldKey);
    if (!oldObject) {
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }
    
    // Copy to new location
    await env.R2_BUCKET.put(newKey, oldObject.body, {
      httpMetadata: oldObject.httpMetadata
    });
    
    // Delete old file
    await env.R2_BUCKET.delete(oldKey);
    
    return jsonResponse({ success: true, message: '重命名成功', newPath: '/' + newKey });
  } catch (e) {
    return jsonResponse({ success: false, message: '重命名失败: ' + e.message }, 500);
  }
}

async function handleCreateFolder(request, env) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const body = await request.json();
    let { path: folderPath } = body;
    
    if (!folderPath) {
      return jsonResponse({ success: false, message: '请提供文件夹路径' }, 400);
    }
    
    if (folderPath.startsWith('/')) folderPath = folderPath.slice(1);
    if (!folderPath.endsWith('/')) folderPath += '/';
    
    // Create an empty placeholder file to represent the folder
    await env.R2_BUCKET.put(folderPath + '.folder', new Uint8Array(0));
    
    return jsonResponse({ success: true, message: '文件夹创建成功', path: '/' + folderPath.slice(0, -1) });
  } catch (e) {
    return jsonResponse({ success: false, message: '创建文件夹失败: ' + e.message }, 500);
  }
}

async function handleDownloadFile(request, env, path) {
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return jsonResponse({ success: false, message: '未授权' }, 401);
  }
  
  try {
    let key = path || '';
    if (key.startsWith('/')) key = key.slice(1);
    
    const object = await env.R2_BUCKET.get(key);
    if (!object) {
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }
    
    const filename = key.split('/').pop();
    
    return new Response(object.body, {
      headers: {
        'Content-Type': object.httpMetadata?.contentType || getMimeType(filename),
        'Content-Disposition': `attachment; filename="${encodeURIComponent(filename)}"`,
        'Content-Length': object.size
      }
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '下载失败: ' + e.message }, 500);
  }
}

// Preview file handler - returns file content for inline viewing
async function handlePreviewFile(request, env, path) {
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return jsonResponse({ success: false, message: '未授权' }, 401);
  }
  
  try {
    let key = path || '';
    if (key.startsWith('/')) key = key.slice(1);
    
    const object = await env.R2_BUCKET.get(key);
    if (!object) {
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }
    
    const filename = key.split('/').pop();
    const contentType = object.httpMetadata?.contentType || getMimeType(filename);
    
    return new Response(object.body, {
      headers: {
        'Content-Type': contentType,
        'Content-Length': object.size,
        'Cache-Control': 'private, max-age=3600'
      }
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '预览失败: ' + e.message }, 500);
  }
}

// ============================================================================
// SHARE HANDLERS
// ============================================================================

async function handleCreateShare(request, env) {
  const auth = await requireAuth(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const body = await request.json();
    const { filePath, password, expiresIn } = body;
    
    if (!filePath) {
      return jsonResponse({ success: false, message: '请提供文件路径' }, 400);
    }
    
    // Verify file exists
    let key = filePath;
    if (key.startsWith('/')) key = key.slice(1);
    
    const object = await env.R2_BUCKET.head(key);
    if (!object) {
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }
    
    const shareId = generateId(12);
    const shareData = {
      shareId,
      filePath: key,
      fileName: key.split('/').pop(),
      fileSize: object.size,
      passwordHash: password ? await hashPassword(password) : null,
      expiresAt: getExpirationTime(expiresIn || '1d'),
      viewCount: 0,
      downloadCount: 0,
      createdAt: Date.now()
    };
    
    await env.KV_STORE.put(`share:${shareId}`, JSON.stringify(shareData));
    
    // Update stats
    const totalShares = parseInt(await env.KV_STORE.get('stats:totalShares') || '0');
    await env.KV_STORE.put('stats:totalShares', String(totalShares + 1));
    
    return jsonResponse({
      success: true,
      shareId,
      shareUrl: `/s/${shareId}`
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '创建分享链接失败: ' + e.message }, 500);
  }
}

async function handleGetShareInfo(request, env, shareId) {
  try {
    const shareData = await env.KV_STORE.get(`share:${shareId}`);
    if (!shareData) {
      return jsonResponse({ success: false, message: '分享链接不存在' }, 404);
    }
    
    const share = JSON.parse(shareData);
    
    // Check expiration
    if (share.expiresAt && Date.now() > share.expiresAt) {
      return jsonResponse({ success: false, message: '分享链接已过期' }, 410);
    }
    
    // Update view count
    share.viewCount++;
    await env.KV_STORE.put(`share:${shareId}`, JSON.stringify(share));
    
    // Update global stats
    const totalViews = parseInt(await env.KV_STORE.get('stats:totalViews') || '0');
    await env.KV_STORE.put('stats:totalViews', String(totalViews + 1));
    
    return jsonResponse({
      success: true,
      fileName: share.fileName,
      fileSize: share.fileSize,
      fileSizeFormatted: formatFileSize(share.fileSize),
      requiresPassword: !!share.passwordHash,
      expiresAt: share.expiresAt
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取分享信息失败: ' + e.message }, 500);
  }
}

async function handleShareDownload(request, env, shareId) {
  try {
    const shareData = await env.KV_STORE.get(`share:${shareId}`);
    if (!shareData) {
      return jsonResponse({ success: false, message: '分享链接不存在' }, 404);
    }
    
    const share = JSON.parse(shareData);
    
    // Check expiration
    if (share.expiresAt && Date.now() > share.expiresAt) {
      return jsonResponse({ success: false, message: '分享链接已过期' }, 410);
    }
    
    // Check password
    if (share.passwordHash) {
      const body = await request.json();
      const { password } = body;
      
      if (!password) {
        return jsonResponse({ success: false, message: '请输入密码' }, 401);
      }
      
      const passwordHash = await hashPassword(password);
      if (passwordHash !== share.passwordHash) {
        return jsonResponse({ success: false, message: '密码错误' }, 401);
      }
    }
    
    // Get file from R2
    const object = await env.R2_BUCKET.get(share.filePath);
    if (!object) {
      return jsonResponse({ success: false, message: '文件不存在' }, 404);
    }
    
    // Update download count
    share.downloadCount++;
    await env.KV_STORE.put(`share:${shareId}`, JSON.stringify(share));
    
    // Update global stats
    const totalDownloads = parseInt(await env.KV_STORE.get('stats:totalDownloads') || '0');
    await env.KV_STORE.put('stats:totalDownloads', String(totalDownloads + 1));
    
    return new Response(object.body, {
      headers: {
        'Content-Type': object.httpMetadata?.contentType || getMimeType(share.fileName),
        'Content-Disposition': `attachment; filename="${encodeURIComponent(share.fileName)}"`,
        'Content-Length': object.size
      }
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '下载失败: ' + e.message }, 500);
  }
}

// ============================================================================
// ADMIN HANDLERS
// ============================================================================

async function handleGetStats(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const totalShares = parseInt(await env.KV_STORE.get('stats:totalShares') || '0');
    const totalViews = parseInt(await env.KV_STORE.get('stats:totalViews') || '0');
    const totalDownloads = parseInt(await env.KV_STORE.get('stats:totalDownloads') || '0');
    
    return jsonResponse({
      success: true,
      totalShares,
      totalViews,
      totalDownloads
    });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取统计数据失败: ' + e.message }, 500);
  }
}

async function handleListShares(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const shares = [];
    let cursor;
    
    do {
      const listed = await env.KV_STORE.list({ prefix: 'share:', cursor });
      for (const key of listed.keys) {
        const data = await env.KV_STORE.get(key.name);
        if (data) {
          const share = JSON.parse(data);
          shares.push({
            ...share,
            fileSizeFormatted: formatFileSize(share.fileSize),
            isExpired: share.expiresAt && Date.now() > share.expiresAt
          });
        }
      }
      cursor = listed.list_complete ? null : listed.cursor;
    } while (cursor);
    
    // Sort by creation date, newest first
    shares.sort((a, b) => b.createdAt - a.createdAt);
    
    return jsonResponse({ success: true, shares });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取分享列表失败: ' + e.message }, 500);
  }
}

async function handleDeleteShare(request, env, shareId) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    await env.KV_STORE.delete(`share:${shareId}`);
    
    // Update stats
    const totalShares = parseInt(await env.KV_STORE.get('stats:totalShares') || '0');
    if (totalShares > 0) {
      await env.KV_STORE.put('stats:totalShares', String(totalShares - 1));
    }
    
    return jsonResponse({ success: true, message: '分享链接已删除' });
  } catch (e) {
    return jsonResponse({ success: false, message: '删除分享链接失败: ' + e.message }, 500);
  }
}

async function handleListUsers(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const users = [];
    let cursor;
    
    do {
      const listed = await env.KV_STORE.list({ prefix: 'user:', cursor });
      for (const key of listed.keys) {
        const data = await env.KV_STORE.get(key.name);
        if (data) {
          const user = JSON.parse(data);
          users.push({
            email: user.email,
            role: user.role,
            createdAt: user.createdAt
          });
        }
      }
      cursor = listed.list_complete ? null : listed.cursor;
    } while (cursor);
    
    return jsonResponse({ success: true, users });
  } catch (e) {
    return jsonResponse({ success: false, message: '获取用户列表失败: ' + e.message }, 500);
  }
}

async function handleCreateUser(request, env) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const body = await request.json();
    const { email, password } = body;
    
    if (!email || !password) {
      return jsonResponse({ success: false, message: '请提供邮箱和密码' }, 400);
    }
    
    // Check if user already exists
    const existing = await env.KV_STORE.get(`user:${email}`);
    if (existing) {
      return jsonResponse({ success: false, message: '用户已存在' }, 409);
    }
    
    const userData = {
      email,
      passwordHash: await hashPassword(password),
      role: 'user',
      createdAt: Date.now()
    };
    
    await env.KV_STORE.put(`user:${email}`, JSON.stringify(userData));
    
    return jsonResponse({ success: true, message: '用户创建成功', email });
  } catch (e) {
    return jsonResponse({ success: false, message: '创建用户失败: ' + e.message }, 500);
  }
}

async function handleDeleteUser(request, env, email) {
  const auth = await requireAdmin(request, env);
  if (auth instanceof Response) return auth;
  
  try {
    const decodedEmail = decodeURIComponent(email);
    await env.KV_STORE.delete(`user:${decodedEmail}`);
    
    return jsonResponse({ success: true, message: '用户已删除' });
  } catch (e) {
    return jsonResponse({ success: false, message: '删除用户失败: ' + e.message }, 500);
  }
}

async function handleCheckAuth(request, env) {
  const auth = await verifyAuth(request, env);
  if (!auth) {
    return jsonResponse({ authenticated: false });
  }
  return jsonResponse({ authenticated: true, role: auth.role, email: auth.email });
}

// ============================================================================
// HTML PAGES
// ============================================================================


/**
 * EdgeStash - Cloudflare-based Cloud Drive
 * Google Drive UI Style
 */

// ... [后端逻辑保持不变，从这里开始向下直到 CSS_STYLES] ...


// ============================================================================
// HTML PAGES - UI UPDATES by Rex2516S
// ============================================================================

const CSS_STYLES = `
<style>
  :root {
    --primary: #1a73e8; /* Google Blue */
    --primary-hover: #1765cc;
    --bg-body: #f7f9fc;
    --bg-surface: #ffffff;
    --text-main: #202124;
    --text-sub: #5f6368;
    --border: #dadce0;
    --hover-bg: #f1f3f4;
    --selection: #e8f0fe;
    --danger: #d93025;
    --success: #188038;
    --sidebar-width: 256px;
    --header-height: 64px;
    --shadow-card: 0 1px 2px 0 rgba(60,64,67,0.3), 0 1px 3px 1px rgba(60,64,67,0.15);
    --shadow-menu: 0 2px 6px 2px rgba(60,64,67,0.15);
  }
  
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Google Sans', 'Roboto', 'Segoe UI', Arial, sans-serif;
  }
  
  body {
    background-color: var(--bg-body);
    color: var(--text-main);
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  
  /* Icons SVG reset */
  svg {
    fill: currentColor;
    width: 24px;
    height: 24px;
  }

  /* --- HEADER --- */
  .header {
    height: var(--header-height);
    background: var(--bg-surface);
    display: flex;
    align-items: center;
    padding: 0 20px;
    border-bottom: 1px solid var(--border);
    justify-content: space-between;
    z-index: 100;
  }
  
  .logo-area {
    display: flex;
    align-items: center;
    gap: 12px;
    min-width: 230px;
  }
  
  .logo-icon {
    width: 40px;
    height: 40px;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  
  .logo-text {
    font-size: 22px;
    color: var(--text-sub);
    font-weight: 400;
  }
  
  .search-bar {
    flex: 1;
    max-width: 720px;
    background: #f1f3f4;
    border-radius: 8px;
    height: 46px;
    display: flex;
    align-items: center;
    padding: 0 16px;
    gap: 12px;
    transition: background 0.2s, box-shadow 0.2s;
  }
  
  .search-bar:focus-within {
    background: var(--bg-surface);
    box-shadow: 0 1px 1px 0 rgba(65,69,73,0.3), 0 1px 3px 1px rgba(65,69,73,0.15);
  }
  
  .search-input {
    border: none;
    background: transparent;
    flex: 1;
    font-size: 16px;
    color: var(--text-main);
    outline: none;
  }
  
  .header-profile {
    display: flex;
    gap: 16px;
    align-items: center;
    min-width: 100px;
    justify-content: flex-end;
  }
  
  .icon-btn {
    width: 40px;
    height: 40px;
    border-radius: 50%;
    border: none;
    background: transparent;
    cursor: pointer;
    color: var(--text-sub);
    display: flex;
    align-items: center;
    justify-content: center;
  }
  
  .icon-btn:hover {
    background: rgba(0,0,0,0.04);
  }

  /* --- LAYOUT --- */
  .main-container {
    display: flex;
    flex: 1;
    overflow: hidden;
  }
  
  /* --- SIDEBAR --- */
  .sidebar {
    width: var(--sidebar-width);
    background: var(--bg-surface);
    display: flex;
    flex-direction: column;
    padding: 16px 0;
  }
  
  .new-btn-wrapper {
    padding: 0 16px 16px 16px;
  }
  
  .btn-new {
    display: flex;
    align-items: center;
    gap: 12px;
    background: var(--bg-surface);
    border: 1px solid var(--border);
    box-shadow: 0 1px 2px 0 rgba(60,64,67,0.3);
    border-radius: 24px;
    padding: 0 24px 0 16px;
    height: 48px;
    cursor: pointer;
    transition: all 0.2s;
    min-width: 120px;
  }
  
  .btn-new:hover {
    box-shadow: 0 4px 8px 3px rgba(60,64,67,0.15);
    background: #f8fafe;
  }
  
  .btn-new-text {
    font-size: 14px;
    font-weight: 500;
    color: var(--text-main);
  }

  .btn-new-plus {
    width: 24px;
    height: 24px;
  }

  /* Sidebar dropdown for "New" */
  .new-dropdown {
    position: absolute;
    top: 120px;
    left: 20px;
    background: white;
    border-radius: 8px;
    box-shadow: var(--shadow-menu);
    width: 200px;
    display: none;
    flex-direction: column;
    padding: 8px 0;
    z-index: 200;
  }
  
  .new-dropdown.active {
    display: flex;
  }
  
  .menu-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    cursor: pointer;
    color: var(--text-main);
    font-size: 14px;
  }
  
  .menu-item:hover {
    background: var(--hover-bg);
  }
  
  .nav-menu {
    display: flex;
    flex-direction: column;
  }
  
  .nav-item {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 10px 24px;
    cursor: pointer;
    color: var(--text-main);
    font-size: 14px;
    border-radius: 0 24px 24px 0;
    margin-right: 16px;
  }
  
  .nav-item:hover {
    background: var(--hover-bg);
  }
  
  .nav-item.active {
    background: #e8f0fe;
    color: var(--primary);
    font-weight: 500;
  }
  
  /* --- CONTENT AREA --- */
  .content-area {
    flex: 1;
    background: var(--bg-surface);
    margin: 16px 16px 16px 0;
    border-radius: 16px;
    padding: 0 24px;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    position: relative;
  }
  
  /* Breadcrumbs */
  .toolbar-top {
    height: 64px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid transparent;
  }
  
  .breadcrumb {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  
  .breadcrumb-item {
    padding: 8px 12px;
    border-radius: 8px;
    color: var(--text-sub);
    text-decoration: none;
    font-size: 18px;
    cursor: pointer;
  }
  
  .breadcrumb-item:hover {
    background: var(--hover-bg);
    color: var(--text-main);
  }
  
  .breadcrumb-item.active {
    color: var(--text-main);
    font-weight: 400;
    cursor: default;
  }
  
  .breadcrumb-item.active:hover {
    background: transparent;
  }

  /* File Grid */
  .file-container {
    flex: 1;
    overflow-y: auto;
    padding-bottom: 40px;
  }
  
  .section-title {
    font-size: 14px;
    font-weight: 500;
    color: var(--text-sub);
    margin: 16px 0 12px 0;
  }
  
  .grid-view {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(210px, 1fr));
    gap: 16px;
  }
  
  .grid-item {
    background: var(--bg-surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    height: 200px;
    display: flex;
    flex-direction: column;
    cursor: pointer;
    transition: background 0.1s, box-shadow 0.1s;
    position: relative;
  }
  
  .grid-item:hover {
    background: #f8fafe;
    box-shadow: 0 1px 3px rgba(0,0,0,0.12);
  }
  
  .grid-item.selected {
    background: #e8f0fe;
    border-color: var(--primary);
  }
  
  .item-preview {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #f1f3f4;
    border-radius: 8px 8px 0 0;
    overflow: hidden;
    font-size: 64px;
  }

  .item-preview img {
    width: 100%;
    height: 100%;
    object-fit: cover;
  }
  
  .item-footer {
    height: 48px;
    display: flex;
    align-items: center;
    padding: 0 12px;
    gap: 12px;
    background: white;
    border-radius: 0 0 8px 8px;
    border-top: 1px solid transparent;
  }
  
  .item-icon {
    font-size: 20px;
    width: 24px;
    text-align: center;
  }
  
  .item-name {
    flex: 1;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-main);
  }

  .item-menu-btn {
    opacity: 0;
    padding: 4px;
    border-radius: 50%;
    cursor: pointer;
  }
  
  .grid-item:hover .item-menu-btn {
    opacity: 1;
  }
  
  .item-menu-btn:hover {
    background: rgba(0,0,0,0.1);
  }
  
  /* Context Menu */
  .context-menu {
    position: fixed;
    background: white;
    border-radius: 4px;
    box-shadow: var(--shadow-menu);
    padding: 6px 0;
    z-index: 1000;
    min-width: 200px;
    display: none;
  }
  
  .context-menu.active {
    display: block;
  }
  
  .context-item {
    padding: 8px 16px;
    display: flex;
    align-items: center;
    gap: 12px;
    font-size: 14px;
    color: var(--text-main);
    cursor: pointer;
  }
  
  .context-item:hover {
    background: var(--hover-bg);
  }
  
  .context-divider {
    height: 1px;
    background: var(--border);
    margin: 6px 0;
  }
  
  .context-item.danger {
    color: var(--danger);
  }
  
  /* Modals */
  .modal-overlay {
    background: rgba(0,0,0,0.4);
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 2000;
    opacity: 0;
    visibility: hidden;
    transition: 0.2s;
  }
  
  .modal-overlay.active {
    opacity: 1;
    visibility: visible;
  }
  
  .modal {
    background: white;
    border-radius: 8px;
    width: 400px;
    padding: 24px;
    box-shadow: 0 24px 38px 3px rgba(0,0,0,0.14);
  }
  
  .modal-title {
    font-size: 22px;
    margin-bottom: 16px;
    color: var(--text-main);
  }
  
  .form-group {
    margin-bottom: 20px;
  }
  
  .form-label {
    display: block;
    margin-bottom: 8px;
    font-size: 14px;
    color: var(--text-sub);
  }
  
  .form-input {
    width: 100%;
    padding: 10px 12px;
    border: 1px solid var(--primary);
    border-radius: 4px;
    font-size: 16px;
    outline: none;
  }
  
  .modal-actions {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    margin-top: 24px;
  }
  
  .btn {
    padding: 8px 24px;
    border-radius: 4px;
    font-weight: 500;
    font-size: 14px;
    cursor: pointer;
    border: none;
    transition: 0.2s;
  }
  
  .btn-text {
    background: transparent;
    color: var(--primary);
  }
  
  .btn-text:hover {
    background: #f6fafe;
  }
  
  .btn-primary {
    background: var(--primary);
    color: white;
  }
  
  .btn-primary:hover {
    background: var(--primary-hover);
    box-shadow: 0 1px 2px rgba(60,64,67,0.3);
  }

  /* Empty State */
  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    color: var(--text-sub);
  }
  
  .empty-img {
    width: 200px;
    margin-bottom: 24px;
    opacity: 0.6;
  }

  /* Toast */
  .toast-container {
    position: fixed;
    bottom: 24px;
    left: 24px;
    z-index: 3000;
  }
  
  .toast {
    background: #323232;
    color: white;
    padding: 14px 24px;
    border-radius: 4px;
    margin-top: 10px;
    display: flex;
    align-items: center;
    gap: 12px;
    box-shadow: 0 2px 5px rgba(0,0,0,0.2);
    animation: slideUp 0.3s ease;
  }
  
  @keyframes slideUp {
    from { transform: translateY(100%); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
  }
  
  /* Mobile Responsive */
  @media (max-width: 768px) {
    .sidebar { display: none; }
    .content-area { margin: 0; padding: 10px; border-radius: 0; }
    .search-bar { display: none; } /* Simplify for mobile */
    .header-mobile-menu { display: block; }
  }
  
  /* Preview & Loader styles reused but simplified */
  .loading-overlay {
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(255,255,255,0.8);
    display: flex; justify-content: center; align-items: center;
    z-index: 5000;
  }
  .spinner {
    border: 4px solid #f3f3f3; border-top: 4px solid var(--primary);
    border-radius: 50%; width: 40px; height: 40px;
    animation: spin 1s linear infinite;
  }
  @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
  
  /* Login Specific */
  .login-container {
    height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: white;
  }
  
  .login-card {
    width: 100%;
    max-width: 450px;
    padding: 48px 40px 36px;
    border: 1px solid var(--border);
    border-radius: 8px;
    text-align: center;
  }
  
  .login-logo {
    color: var(--text-main);
    font-size: 24px;
    margin-bottom: 40px;
  }
  
  .form-input-clean {
    width: 100%;
    padding: 13px 15px;
    border: 1px solid var(--border);
    border-radius: 4px;
    margin-bottom: 20px;
    font-size: 16px;
    transition: 0.2s;
  }
  
  .form-input-clean:focus {
    border: 2px solid var(--primary);
    padding: 12px 14px; /* compensate border */
    outline: none;
  }
</style>
`;

const LOGIN_PAGE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>登录 - EdgeStash</title>
  ${CSS_STYLES}
</head>
<body>
  <div class="login-container">
    <div class="login-card">
      <div class="login-logo">
        <span style="color:#4285F4">E</span><span style="color:#EA4335">d</span><span style="color:#FBBC05">g</span><span style="color:#4285F4">e</span><span style="color:#34A853">S</span><span style="color:#EA4335">t</span>ash
      </div>
      
      <div style="margin-bottom: 24px;">
        <h1 style="font-size: 24px; font-weight: 400; margin-bottom: 8px;">登录</h1>
        <p style="color: var(--text-sub);">继续使用 EdgeStash 云盘</p>
      </div>
      
      <div style="display: flex; margin-bottom: 24px; border-bottom: 1px solid var(--border);">
        <button id="tabAdmin" class="btn-text" style="flex:1; border-bottom: 2px solid var(--primary); color: var(--primary);" onclick="switchLoginTab('admin')">管理员</button>
        <button id="tabUser" class="btn-text" style="flex:1; color: var(--text-sub);" onclick="switchLoginTab('user')">用户</button>
      </div>

      <form id="loginForm" onsubmit="handleLogin(event)">
        <div id="emailField" style="display: none;">
          <input type="email" id="email" class="form-input-clean" placeholder="电子邮箱">
        </div>
        
        <input type="password" id="password" class="form-input-clean" placeholder="输入密码" required>
        
        <div style="display: flex; justify-content: flex-end; margin-top: 30px;">
          <button type="submit" class="btn btn-primary">下一步</button>
        </div>
      </form>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <script>
    let isAdminLogin = true;
    
    function switchLoginTab(type) {
      isAdminLogin = type === 'admin';
      const adminBtn = document.getElementById('tabAdmin');
      const userBtn = document.getElementById('tabUser');
      
      if (isAdminLogin) {
        adminBtn.style.borderBottom = '2px solid var(--primary)';
        adminBtn.style.color = 'var(--primary)';
        userBtn.style.borderBottom = 'none';
        userBtn.style.color = 'var(--text-sub)';
        document.getElementById('emailField').style.display = 'none';
      } else {
        userBtn.style.borderBottom = '2px solid var(--primary)';
        userBtn.style.color = 'var(--primary)';
        adminBtn.style.borderBottom = 'none';
        adminBtn.style.color = 'var(--text-sub)';
        document.getElementById('emailField').style.display = 'block';
      }
    }
    
    async function handleLogin(e) {
      e.preventDefault();
      
      const password = document.getElementById('password').value;
      const email = document.getElementById('email').value;
      
      try {
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            isAdmin: isAdminLogin,
            email: isAdminLogin ? undefined : email,
            password
          })
        });
        
        const data = await response.json();
        
        if (data.success) {
          window.location.href = '/';
        } else {
          showToast(data.message || '登录失败');
        }
      } catch (error) {
        showToast('登录失败: ' + error.message);
      }
    }
    
    function showToast(message) {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast';
      toast.textContent = message;
      container.appendChild(toast);
      setTimeout(() => toast.remove(), 3000);
    }
  </script>
</body>
</html>
`;

const INDEX_PAGE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>我的云端硬盘 - EdgeStash</title>
  ${CSS_STYLES}
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/mammoth@1.6.0/mammoth.browser.min.js"></script>
</head>
<body>
  <!-- HEADER -->
  <header class="header">
    <div class="logo-area">
      <div class="logo-icon">
        <svg viewBox="0 0 87.3 78" style="width:32px; height:auto;">
          <path d="m6.6 66.85 3.85 6.65c.8 1.4 1.95 2.5 3.3 3.3l13.75-23.8h-27.5c0 1.55.4 3.1 1.2 4.5z" fill="#0066da"/>
          <path d="m43.65 25-13.75-23.8c-1.35.8-2.5 1.9-3.3 3.3l-25.4 44a9.06 9.06 0 0 0 -1.2 4.5h27.5z" fill="#00ac47"/>
          <path d="m73.55 76.8c1.35-.8 2.5-1.9 3.3-3.3l1.6-2.75 7.65-13.25c.8-1.4 1.2-2.95 1.2-4.5h-27.502l5.852 11.5z" fill="#ea4335"/>
          <path d="m43.65 25 13.75-23.8c-1.35-.8-2.9-1.2-4.5-1.2h-18.5c-1.6 0-3.15.45-4.5 1.2z" fill="#00832d"/>
          <path d="m59.8 53h-27.5l13.75 23.8c1.35-.8 2.5-1.9 3.3-3.3l13.75-23.8z" fill="#2684fc"/>
          <path d="m73.4 26.5-12.7-22c-.8-1.4-1.95-2.5-3.3-3.3l-13.75 23.8 29.75 51.5c1.35-.8 2.5-1.9 3.3-3.3l7.65-13.25c.8-1.4 1.2-2.95 1.2-4.5 0-1.55-.4-3.1-1.2-4.5z" fill="#ffba00"/>
        </svg>
      </div>
      <span class="logo-text">EdgeStash</span>
    </div>
    
    <div class="search-bar">
      <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368"><path d="M15.5 14h-.79l-.28-.27C15.41 12.59 16 11.11 16 9.5 16 5.91 13.09 3 9.5 3S3 5.91 3 9.5 5.91 16 9.5 16c1.61 0 3.09-.59 4.23-1.57l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z"/></svg>
      <input type="text" class="search-input" placeholder="在云端硬盘中搜索" oninput="filterFiles(this.value)">
      <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368; cursor:pointer;"><path d="M3 17v2h6v-2H3zM3 5v2h10V5H3zm10 16v-2h8v-2h-8v-2h-2v6h2zM7 9v2H3v2h4v2h2V9H7zm14 4v-2H11v2h10zm-6-4h2V7h4V5h-4V3h-2v6z"/></svg>
    </div>
    
    <div class="header-profile">
      <button class="icon-btn" title="管理后台" onclick="window.location.href='/admin.html'">
        <svg viewBox="0 0 24 24"><path d="M19.43 12.98c.04-.32.07-.64.07-.98s-.03-.66-.07-.98l2.11-1.65c.19-.15.24-.42.12-.64l-2-3.46c-.12-.22-.39-.3-.61-.22l-2.49 1c-.52-.4-1.08-.73-1.69-.98l-.38-2.65C14.46 2.18 14.25 2 14 2h-4c-.25 0-.46.18-.49.42l-.38 2.65c-.61.25-1.17.59-1.69.98l-2.49-1c-.23-.09-.49 0-.61.22l-2 3.46c-.13.22-.07.49.12.64l2.11 1.65c-.04.32-.07.65-.07.98s.03.66.07.98l-2.11 1.65c-.19.15-.24.42-.12.64l2 3.46c.12.22.39.3.61.22l2.49-1c.52.4 1.08.73 1.69.98l.38 2.65c.03.24.24.42.49.42h4c.25 0 .46-.18.49-.42l.38-2.65c.61-.25 1.17-.59 1.69-.98l2.49 1c.23.09.49 0 .61-.22l2-3.46c.12-.22.07-.49-.12-.64l-2.11-1.65zM12 15.5c-1.93 0-3.5-1.57-3.5-3.5s1.57-3.5 3.5-3.5 3.5 1.57 3.5 3.5-1.57 3.5-3.5 3.5z"/></svg>
      </button>
      <button class="icon-btn" title="退出" onclick="logout()">
        <svg viewBox="0 0 24 24"><path d="M10.09 15.59L11.5 17l5-5-5-5-1.41 1.41L12.67 11H3v2h9.67l-2.58 2.59zM19 3H5c-1.11 0-2 .9-2 2v4h2V5h14v14H5v-4H3v4c0 1.1.89 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/></svg>
      </button>
    </div>
  </header>
  
  <div class="main-container">
    <!-- SIDEBAR -->
    <aside class="sidebar">
      <div class="new-btn-wrapper">
        <button class="btn-new" onclick="toggleNewMenu()">
          <svg class="btn-new-plus" viewBox="0 0 24 24"><path d="M19 13h-6v6h-2v-6H5v-2h6V5h2v6h6v2z" fill="#000" fill-opacity="0.54"/></svg>
          <span class="btn-new-text">新建</span>
        </button>
        <div class="new-dropdown" id="newDropdown">
          <div class="menu-item" onclick="showNewFolderModal()">
            <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
            <span>新建文件夹</span>
          </div>
          <div class="menu-item" onclick="document.getElementById('fileInput').click()">
            <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368"><path d="M9 16h6v-6h4l-7-7-7 7h4zm-4 2h14v2H5z"/></svg>
            <span>上传文件</span>
          </div>
        </div>
      </div>
      
      <div class="nav-menu">
        <div class="nav-item active" onclick="navigateTo('/')">
          <svg viewBox="0 0 24 24" style="width:20px;"><path d="M19 2H5c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm0 18H5V4h14v16zM11 5.5h2v4h-2zm0 8h2v5h-2z"/></svg>
          <span>我的云端硬盘</span>
        </div>
        <div class="nav-item">
          <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368"><path d="M15 8c0-1.3-.84-2.4-2-2.81V3.5c0-.83-.67-1.5-1.5-1.5S10 2.67 10 3.5v1.69c-1.16.41-2 1.51-2 2.81 0 1.66 1.34 3 3 3s3-1.34 3-3zm8 5c0 1.66-1.34 3-3 3h-2v2.26c1.48.54 2.53 1.95 2.53 3.6 0 2.14-1.74 3.88-3.88 3.88-2.14 0-3.88-1.74-3.88-3.88 0-1.65 1.05-3.06 2.53-3.6V16H12.1c-.63 0-1.23.15-1.77.42-1.21.6-2.5 2.55-2.58 4.58l-.01.35H6.18l.02-.45c.16-3.08 2.05-5.59 4.38-6.68C9.55 13.62 9 12.87 9 12c0-2.21 1.79-4 4-4s4 1.79 4 4c0 .87-.55 1.62-1.4 2.22l.53.56C19.06 13.2 23 11.41 23 13zM6 13c0 1.66-1.34 3-3 3s-3-1.34-3-3 1.34-3 3-3 3 1.34 3 3z"/></svg>
          <span>与我共享</span>
        </div>
      </div>
    </aside>

    <!-- MAIN CONTENT -->
    <div class="content-area" onclick="closeContextMenus()">
      <div class="toolbar-top">
        <div class="breadcrumb" id="breadcrumb"></div>
        <div style="display:flex; gap:8px;">
           <button class="icon-btn" onclick="loadFiles()">
            <svg viewBox="0 0 24 24"><path d="M17.65 6.35C16.2 4.9 14.21 4 12 4c-4.42 0-7.99 3.58-7.99 8s3.57 8 7.99 8c3.73 0 6.84-2.55 7.73-6h-2.08c-.82 2.33-3.04 4-5.65 4-3.31 0-6-2.69-6-6s2.69-6 6-6c1.66 0 3.14.69 4.22 1.78L13 11h7V4l-2.35 2.35z"/></svg>
           </button>
           <button class="icon-btn">
             <svg viewBox="0 0 24 24"><path d="M4 8h4V4H4v4zm6 12h4v-4h-4v4zm-6 0h4v-4H4v4zm0-6h4v-4H4v4zm6 0h4v-4h-4v4zm6-10v4h4V4h-4zm-6 4h4V4h-4v4zm6 6h4v-4h-4v4zm0 6h4v-4h-4v4z"/></svg>
           </button>
        </div>
      </div>
      
      <div class="file-container" id="fileContainer">
        <!-- Render content here -->
      </div>
      
      <div id="emptyState" class="empty-state" style="display: none;">
        <img src="https://ssl.gstatic.com/docs/doclist/images/empty_state_2x.png" class="empty-img">
        <div>这里没有任何内容</div>
        <div style="font-size:14px; margin-top:8px;">将文件拖到这里或使用“新建”按钮</div>
      </div>
    </div>
  </div>

  <!-- HIDDEN INPUT -->
  <input type="file" id="fileInput" multiple style="display: none;" onchange="handleFileUpload(event)">

  <!-- CONTEXT MENU -->
  <div class="context-menu" id="contextMenu">
    <div class="context-item" id="ctxPreview" onclick="ctxAction('preview')">
      <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368"><path d="M12 4.5C7 4.5 2.73 7.61 1 12c1.73 4.39 6 7.5 11 7.5s9.27-3.11 11-7.5c-1.73-4.39-6-7.5-11-7.5zM12 17c-2.76 0-5-2.24-5-5s2.24-5 5-5 5 2.24 5 5-2.24 5-5 5zm0-8c-1.66 0-3 1.34-3 3s1.34 3 3 3 3-1.34 3-3-1.34-3-3-3z"/></svg>
      预览
    </div>
    <div class="context-item" onclick="ctxAction('download')">
      <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368"><path d="M19 9h-4V3H9v6H5l7 7 7-7zM5 18v2h14v-2H5z"/></svg>
      下载
    </div>
    <div class="context-item" onclick="ctxAction('rename')">
      <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zM20.71 7.04c.39-.39.39-1.02 0-1.41l-2.34-2.34c-.39-.39-1.02-.39-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z"/></svg>
      重命名
    </div>
    <div class="context-item" onclick="ctxAction('share')">
      <svg viewBox="0 0 24 24" style="width:20px; fill:#5f6368"><path d="M18 16.08c-.76 0-1.44.3-1.96.77L8.91 12.7c.05-.23.09-.46.09-.7s-.04-.47-.09-.7l7.05-4.11c.54.5 1.25.81 2.04.81 1.66 0 3-1.34 3-3s-1.34-3-3-3-3 1.34-3 3c0 .24.04.47.09.7L8.04 9.81C7.5 9.31 6.79 9 6 9c-1.66 0-3 1.34-3 3s1.34 3 3 3c.79 0 1.5-.31 2.04-.81l7.12 4.16c-.05.21-.08.43-.08.65 0 1.61 1.31 2.92 2.92 2.92 1.61 0 2.92-1.31 2.92-2.92s-1.31-2.92-2.92-2.92z"/></svg>
      获取分享链接
    </div>
    <div class="context-divider"></div>
    <div class="context-item danger" onclick="ctxAction('delete')">
      <svg viewBox="0 0 24 24" style="width:20px; fill:currentColor"><path d="M6 19c0 1.1.9 2 2 2h8c1.1 0 2-.9 2-2V7H6v12zM19 4h-3.5l-1-1h-5l-1 1H5v2h14V4z"/></svg>
      删除
    </div>
  </div>

  <!-- MODALS -->
  <div class="modal-overlay" id="newFolderModal">
    <div class="modal">
      <div class="modal-title">新建文件夹</div>
      <form onsubmit="createFolder(event)">
        <div class="form-group">
          <input type="text" id="folderName" class="form-input" placeholder="文件夹名称" required autofocus>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-text" onclick="closeModal('newFolderModal')">取消</button>
          <button type="submit" class="btn btn-primary">创建</button>
        </div>
      </form>
    </div>
  </div>

  <div class="modal-overlay" id="renameModal">
    <div class="modal">
      <div class="modal-title">重命名</div>
      <form onsubmit="renameFile(event)">
        <div class="form-group">
          <input type="text" id="newFileName" class="form-input" required>
        </div>
        <input type="hidden" id="renameFilePath">
        <div class="modal-actions">
          <button type="button" class="btn btn-text" onclick="closeModal('renameModal')">取消</button>
          <button type="submit" class="btn btn-primary">确定</button>
        </div>
      </form>
    </div>
  </div>

  <div class="modal-overlay" id="shareModal">
    <div class="modal">
      <div class="modal-title">创建分享链接</div>
      <form onsubmit="createShare(event)">
        <div class="form-group">
          <label class="form-label">密码（可选）</label>
          <input type="text" id="sharePassword" class="form-input" placeholder="无密码">
        </div>
        <div class="form-group">
          <label class="form-label">有效期</label>
          <select id="shareExpiry" class="form-input">
            <option value="1h">1小时</option>
            <option value="1d" selected>1天</option>
            <option value="1m">1个月</option>
            <option value="permanent">永久有效</option>
          </select>
        </div>
        <input type="hidden" id="shareFilePath">
        <div class="modal-actions">
          <button type="button" class="btn btn-text" onclick="closeModal('shareModal')">取消</button>
          <button type="submit" class="btn btn-primary">创建链接</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Preview Modal -->
  <div class="modal-overlay" id="previewOverlay" style="z-index: 2500;">
    <div style="position:absolute; top:10px; right:10px; z-index:2600;">
       <button class="icon-btn" style="color:white; background:rgba(0,0,0,0.5);" onclick="closePreview()">
         <svg viewBox="0 0 24 24"><path d="M19 6.41L17.59 5 12 10.59 6.41 5 5 6.41 10.59 12 5 17.59 6.41 19 12 13.41 17.59 19 19 17.59 13.41 12z"/></svg>
       </button>
    </div>
    <div id="previewContent" style="width:80%; height:80%; background:white; border-radius:8px; overflow:hidden; display:flex; justify-content:center; align-items:center;">
    </div>
  </div>

  <div class="loading-overlay" id="loadingOverlay" style="display: none;">
    <div class="spinner"></div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>

  <script>
    let currentPath = '/';
    let ctxFile = null;
    let allFiles = []; // For filtering
    
    // Auth Check
    async function checkAuth() {
      try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        if (!data.authenticated) window.location.href = '/login.html';
      } catch (error) { window.location.href = '/login.html'; }
    }
    
    async function loadFiles() {
      showLoading(true);
      try {
        const response = await fetch('/api/files' + currentPath);
        const data = await response.json();
        if (!data.success) {
          if (response.status === 401) return window.location.href = '/login.html';
          throw new Error(data.message);
        }
        
        allFiles = { folders: data.folders, files: data.files };
        renderBreadcrumb();
        renderFiles(data.folders, data.files);
      } catch (error) {
        showToast('加载失败: ' + error.message);
      } finally {
        showLoading(false);
      }
    }
    
    function filterFiles(query) {
      if(!query) {
        renderFiles(allFiles.folders, allFiles.files);
        return;
      }
      query = query.toLowerCase();
      const filteredFolders = allFiles.folders.filter(f => f.name.toLowerCase().includes(query));
      const filteredFiles = allFiles.files.filter(f => f.name.toLowerCase().includes(query));
      renderFiles(filteredFolders, filteredFiles);
    }
    
    function renderBreadcrumb() {
      const breadcrumb = document.getElementById('breadcrumb');
      const parts = currentPath.split('/').filter(p => p);
      let html = '<div class="breadcrumb-item" onclick="navigateTo(\\'/\\')">云端硬盘</div>';
      
      let path = '';
      parts.forEach((part, index) => {
        path += '/' + part;
        const isLast = index === parts.length - 1;
        html += '<svg viewBox="0 0 24 24" style="width:18px; color:var(--text-sub);"><path d="M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"/></svg>';
        if (isLast) {
          html += '<div class="breadcrumb-item active">' + escapeHtml(part) + '</div>';
        } else {
          html += '<div class="breadcrumb-item" onclick="navigateTo(\\'' + path + '\\')">' + escapeHtml(part) + '</div>';
        }
      });
      breadcrumb.innerHTML = html;
    }
    
    function renderFiles(folders, files) {
      const container = document.getElementById('fileContainer');
      const emptyState = document.getElementById('emptyState');
      
      if (folders.length === 0 && files.length === 0) {
        container.innerHTML = '';
        emptyState.style.display = 'flex';
        return;
      }
      
      emptyState.style.display = 'none';
      let html = '';
      
      // Folders
      if (folders.length > 0) {
        html += '<div class="section-title">文件夹</div><div class="grid-view">';
        folders.forEach(folder => {
          html += \`
            <div class="grid-item" ondblclick="navigateTo('\${folder.path}')" oncontextmenu="openContextMenu(event, 'folder', '\${folder.path}', '\${escapeHtml(folder.name)}')">
              <div class="item-preview" style="background:#fff; border-bottom:1px solid var(--border);">
                 <svg viewBox="0 0 24 24" style="width:64px; height:64px; fill:#5f6368"><path d="M10 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2h-8l-2-2z"/></svg>
              </div>
              <div class="item-footer">
                <div class="item-name">\${escapeHtml(folder.name)}</div>
                <div class="item-menu-btn" onclick="openContextMenu(event, 'folder', '\${folder.path}', '\${escapeHtml(folder.name)}')">
                   <svg viewBox="0 0 24 24" style="width:18px;"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                </div>
              </div>
            </div>
          \`;
        });
        html += '</div>';
      }
      
      // Files
      if (files.length > 0) {
        html += '<div class="section-title">文件</div><div class="grid-view">';
        files.forEach(file => {
          const previewType = file.previewType || '';
          const icon = getFileIconSvg(file.name);
          html += \`
            <div class="grid-item" ondblclick="handleFileClick('\${file.path}', '\${previewType}', '\${escapeHtml(file.name)}')" oncontextmenu="openContextMenu(event, 'file', '\${file.path}', '\${escapeHtml(file.name)}', '\${previewType}')">
              <div class="item-preview">
                 \${icon}
              </div>
              <div class="item-footer">
                <div class="item-icon">\${icon}</div>
                <div class="item-name" title="\${escapeHtml(file.name)}">\${escapeHtml(file.name)}</div>
                <div class="item-menu-btn" onclick="openContextMenu(event, 'file', '\${file.path}', '\${escapeHtml(file.name)}', '\${previewType}')">
                   <svg viewBox="0 0 24 24" style="width:18px;"><path d="M12 8c1.1 0 2-.9 2-2s-.9-2-2-2-2 .9-2 2 .9 2 2 2zm0 2c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm0 6c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
                </div>
              </div>
            </div>
          \`;
        });
        html += '</div>';
      }
      
      container.innerHTML = html;
    }
    
    function getFileIconSvg(filename) {
       const ext = filename.split('.').pop().toLowerCase();
       // Simplified icons color mapping
       if(['jpg','png','gif','jpeg'].includes(ext)) return '<svg viewBox="0 0 24 24" style="fill:#d93025"><path d="M21 19V5c0-1.1-.9-2-2-2H5c-1.1 0-2 .9-2 2v14c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2zM8.5 13.5l2.5 3.01L14.5 12l4.5 6H5l3.5-4.5z"/></svg>';
       if(['pdf'].includes(ext)) return '<svg viewBox="0 0 24 24" style="fill:#fbbc04"><path d="M20 2H8c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V4c0-1.1-.9-2-2-2zm-8.5 7.5c0 .83-.67 1.5-1.5 1.5H9v2H7.5V7H10c.83 0 1.5.67 1.5 1.5v1zm5 2c0 .83-.67 1.5-1.5 1.5h-2.5V7H15c.83 0 1.5.67 1.5 1.5v3zm4-3H19v1h1.5v1.5H19v2h-1.5V7h2z"/></svg>';
       if(['mp4','mov'].includes(ext)) return '<svg viewBox="0 0 24 24" style="fill:#ea4335"><path d="M18 4l2 4h-3l-2-4h-2l2 4h-3l-2-4H8l2 4H7L5 4H4c-1.1 0-1.99.9-1.99 2L2 18c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V4h-4z"/></svg>';
       return '<svg viewBox="0 0 24 24" style="fill:#4285f4"><path d="M6 2c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6H6zm7 7V3.5L18.5 9H13z"/></svg>';
    }

    function navigateTo(path) {
      currentPath = path;
      loadFiles();
    }
    
    function toggleNewMenu() {
      const menu = document.getElementById('newDropdown');
      menu.classList.toggle('active');
    }
    
    // Global click listener to close menus
    window.addEventListener('click', (e) => {
      if (!e.target.closest('.new-btn-wrapper')) {
        document.getElementById('newDropdown').classList.remove('active');
      }
      if (!e.target.closest('.context-menu') && !e.target.closest('.grid-item')) {
         closeContextMenus();
      }
    });
    
    // --- Context Menu ---
    function openContextMenu(e, type, path, name, previewType) {
      e.preventDefault();
      e.stopPropagation();
      closeContextMenus();
      
      ctxFile = { path, name, type, previewType };
      
      const menu = document.getElementById('contextMenu');
      const previewItem = document.getElementById('ctxPreview');
      
      previewItem.style.display = (type === 'file' && previewType) ? 'flex' : 'none';
      
      // Basic positioning
      menu.style.display = 'block';
      menu.style.left = e.pageX + 'px';
      menu.style.top = e.pageY + 'px';
      
      // Adjust if out of bounds
      const rect = menu.getBoundingClientRect();
      if (rect.right > window.innerWidth) menu.style.left = (window.innerWidth - rect.width - 10) + 'px';
      if (rect.bottom > window.innerHeight) menu.style.top = (window.innerHeight - rect.height - 10) + 'px';
    }
    
    function closeContextMenus() {
      document.getElementById('contextMenu').style.display = 'none';
    }
    
    function ctxAction(action) {
      closeContextMenus();
      if(!ctxFile) return;
      
      switch(action) {
        case 'preview': previewFile(ctxFile.path, ctxFile.previewType, ctxFile.name); break;
        case 'download': downloadFile(ctxFile.path); break;
        case 'rename': showRenameModal(ctxFile.path, ctxFile.name); break;
        case 'share': showShareModal(ctxFile.path); break;
        case 'delete': deleteFile(ctxFile.path); break;
      }
    }
    
    // --- Actions ---
    function handleFileClick(path, previewType, filename) {
      if (previewType) previewFile(path, previewType, filename);
      else downloadFile(path);
    }
    
    function showRenameModal(path, name) {
       document.getElementById('renameFilePath').value = path;
       document.getElementById('newFileName').value = name;
       document.getElementById('renameModal').classList.add('active');
    }
    
    function showNewFolderModal() {
       document.getElementById('newFolderModal').classList.add('active');
       document.getElementById('newDropdown').classList.remove('active');
    }

    function showShareModal(path) {
      document.getElementById('shareFilePath').value = path;
      document.getElementById('shareModal').classList.add('active');
    }
    
    function closeModal(id) {
       document.getElementById(id).classList.remove('active');
    }

    // Reuse existing logic functions (minimized for brevity, assuming standard fetch calls)
    async function createFolder(e) {
      e.preventDefault();
      const name = document.getElementById('folderName').value.trim();
      closeModal('newFolderModal');
      showLoading(true);
      
      let folderPath = currentPath;
      if (!folderPath.endsWith('/')) folderPath += '/';
      folderPath += name;
      
      await apiCall('/api/folders', 'POST', { path: folderPath }, '文件夹创建成功');
      loadFiles();
    }
    
    async function renameFile(e) {
      e.preventDefault();
      const path = document.getElementById('renameFilePath').value;
      const newName = document.getElementById('newFileName').value.trim();
      closeModal('renameModal');
      showLoading(true);
      await apiCall('/api/files' + path, 'PUT', { newName }, '重命名成功');
      loadFiles();
    }
    
    async function deleteFile(path) {
      if(!confirm('确定要删除吗？')) return;
      showLoading(true);
      await apiCall('/api/files' + path, 'DELETE', null, '删除成功');
      loadFiles();
    }
    
    async function handleFileUpload(e) {
      const files = e.target.files;
      if (!files.length) return;
      showLoading(true);
      document.getElementById('newDropdown').classList.remove('active');
      
      for (const file of files) {
        const formData = new FormData();
        formData.append('file', file);
        try {
           await fetch('/api/files' + currentPath, { method: 'POST', body: formData });
           showToast('上传成功: ' + file.name);
        } catch(e) { showToast('上传失败'); }
      }
      e.target.value = '';
      loadFiles();
    }

    async function createShare(e) {
      e.preventDefault();
      const body = {
        filePath: document.getElementById('shareFilePath').value,
        password: document.getElementById('sharePassword').value,
        expiresIn: document.getElementById('shareExpiry').value
      };
      closeModal('shareModal');
      showLoading(true);
      try {
        const res = await fetch('/api/share', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
        const data = await res.json();
        if(data.success) {
           const url = window.location.origin + data.shareUrl;
           navigator.clipboard.writeText(url);
           showToast('链接已复制到剪贴板');
        } else { showToast(data.message); }
      } catch(e) { showToast(e.message); }
      showLoading(false);
    }
    
    async function apiCall(url, method, body, successMsg) {
       try {
         const opts = { method };
         if(body) {
           opts.headers = {'Content-Type': 'application/json'};
           opts.body = JSON.stringify(body);
         }
         const res = await fetch(url, opts);
         const data = await res.json();
         if(data.success) { showToast(successMsg); return true; }
         else { showToast(data.message); return false; }
       } catch(e) {
         showToast(e.message);
         return false;
       } finally { showLoading(false); }
    }
    
    async function downloadFile(path) {
      window.open('/api/download' + path, '_blank');
    }

    // Preview Logic (Simplified)
    async function previewFile(path, type, name) {
       const overlay = document.getElementById('previewOverlay');
       const content = document.getElementById('previewContent');
       overlay.classList.add('active');
       content.innerHTML = '<div class="spinner"></div>';
       
       const url = '/api/preview' + path;
       
       if(type === 'image') content.innerHTML = '<img src="'+url+'" style="max-width:100%; max-height:100%;">';
       else if(type === 'video') content.innerHTML = '<video controls autoplay src="'+url+'" style="max-width:100%;"></video>';
       else if(type === 'audio') content.innerHTML = '<audio controls autoplay src="'+url+'"></audio>';
       else if(type === 'pdf') content.innerHTML = '<iframe src="'+url+'" style="width:100%; height:100%; border:none;"></iframe>';
       else if(type === 'text' || type === 'word') {
          const res = await fetch(url);
          if(type === 'word') {
             const buff = await res.arrayBuffer();
             const resHtml = await mammoth.convertToHtml({arrayBuffer: buff});
             content.innerHTML = '<div style="padding:20px; overflow:auto; width:100%; height:100%;">' + resHtml.value + '</div>';
          } else {
             const text = await res.text();
             const isMd = name.endsWith('.md');
             content.innerHTML = '<div style="padding:20px; overflow:auto; width:100%; height:100%; white-space:pre-wrap; font-family:monospace;">' + (isMd ? marked.parse(text) : escapeHtml(text)) + '</div>';
          }
       }
    }
    
    function closePreview() {
      document.getElementById('previewOverlay').classList.remove('active');
      document.getElementById('previewContent').innerHTML = '';
    }

    function showLoading(show) {
      document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none';
    }
    function showToast(msg) {
       const box = document.getElementById('toastContainer');
       const div = document.createElement('div');
       div.className = 'toast'; div.innerText = msg;
       box.appendChild(div);
       setTimeout(() => div.remove(), 3000);
    }
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      window.location.href = '/login.html';
    }

    checkAuth();
    loadFiles();
  </script>
</body>
</html>
`;



const ADMIN_PAGE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>管理控制台 - EdgeStash</title>
  ${CSS_STYLES}
  <style>
    /* Admin specific styles */
    .admin-container {
      max-width: 1000px;
      margin: 0 auto;
      padding: 24px;
      width: 100%;
    }
    .nav-tabs {
      display: flex;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .nav-tab {
      padding: 12px 24px;
      cursor: pointer;
      font-weight: 500;
      color: var(--text-sub);
      border-bottom: 3px solid transparent;
      transition: color 0.2s;
    }
    .nav-tab:hover {
      color: var(--primary);
      background: var(--hover-bg);
    }
    .nav-tab.active {
      color: var(--primary);
      border-bottom-color: var(--primary);
    }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    
    /* Stats Cards */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 24px;
      margin-bottom: 32px;
    }
    .stat-card {
      background: white;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 24px;
      display: flex;
      flex-direction: column;
    }
    .stat-val {
      font-size: 36px;
      color: var(--text-main);
      font-weight: 400;
      margin-bottom: 8px;
    }
    .stat-label {
      font-size: 14px;
      color: var(--text-sub);
      font-weight: 500;
    }

    /* Tables */
    .table-card {
      background: white;
      border: 1px solid var(--border);
      border-radius: 8px;
      overflow: hidden;
    }
    .table-header {
      padding: 16px 24px;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .table-title { font-size: 18px; font-weight: 400; }
    table { width: 100%; border-collapse: collapse; }
    th {
      text-align: left;
      padding: 12px 24px;
      font-size: 12px;
      font-weight: 500;
      color: var(--text-sub);
      background: #f8f9fa;
      border-bottom: 1px solid var(--border);
    }
    td {
      padding: 14px 24px;
      border-bottom: 1px solid var(--border);
      font-size: 14px;
      color: var(--text-main);
    }
    tr:last-child td { border-bottom: none; }
    tr:hover { background-color: #f8fafe; }
    
    .badge {
      display: inline-block;
      padding: 4px 8px;
      border-radius: 12px;
      font-size: 12px;
      font-weight: 500;
    }
    .badge-green { background: #e6f4ea; color: #137333; }
    .badge-red { background: #fce8e6; color: #c5221f; }
  </style>
</head>
<body>
  <header class="header">
    <div class="logo-area" style="cursor:pointer" onclick="window.location.href='/'">
      <div class="logo-icon">
        <svg viewBox="0 0 24 24" style="fill:#5f6368"><path d="M19.43 12.98c.04-.32.07-.64.07-.98s-.03-.66-.07-.98l2.11-1.65c.19-.15.24-.42.12-.64l-2-3.46c-.12-.22-.39-.3-.61-.22l-2.49 1c-.52-.4-1.08-.73-1.69-.98l-.38-2.65C14.46 2.18 14.25 2 14 2h-4c-.25 0-.46.18-.49.42l-.38 2.65c-.61.25-1.17.59-1.69.98l-2.49-1c-.23-.09-.49 0-.61.22l-2 3.46c-.13.22-.07.49.12.64l2.11 1.65c-.04.32-.07.65-.07.98s.03.66.07.98l-2.11 1.65c-.19.15-.24.42-.12.64l2 3.46c.12.22.39.3.61.22l2.49-1c.52.4 1.08.73 1.69.98l.38 2.65c.03.24.24.42.49.42h4c.25 0 .46-.18.49-.42l.38-2.65c.61-.25 1.17-.59 1.69-.98l2.49 1c.23.09.49 0 .61-.22l2-3.46c.12-.22.07-.49-.12-.64l-2.11-1.65zM12 15.5c-1.93 0-3.5-1.57-3.5-3.5s1.57-3.5 3.5-3.5 3.5 1.57 3.5 3.5-1.57 3.5-3.5 3.5z"/></svg>
      </div>
      <span class="logo-text">管理控制台</span>
    </div>
    <div class="header-profile">
       <button class="btn btn-text" onclick="window.location.href='/'">返回云盘</button>
       <button class="btn btn-primary" onclick="logout()">退出</button>
    </div>
  </header>

  <div class="admin-container">
    <div class="nav-tabs">
      <div class="nav-tab active" onclick="switchTab('stats')">概览</div>
      <div class="nav-tab" onclick="switchTab('shares')">分享链接管理</div>
      <div class="nav-tab" onclick="switchTab('users')">用户管理</div>
    </div>

    <!-- STATS -->
    <div id="statsTab" class="tab-content active">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-val" id="totalShares">-</div>
          <div class="stat-label">活跃分享</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" id="totalViews">-</div>
          <div class="stat-label">总浏览次数</div>
        </div>
        <div class="stat-card">
          <div class="stat-val" id="totalDownloads">-</div>
          <div class="stat-label">总下载次数</div>
        </div>
      </div>
    </div>

    <!-- SHARES -->
    <div id="sharesTab" class="tab-content">
      <div class="table-card">
        <div class="table-header">
          <div class="table-title">所有分享链接</div>
          <button class="btn btn-text" onclick="loadShares()">刷新</button>
        </div>
        <div style="overflow-x:auto;">
          <table>
            <thead>
              <tr>
                <th>文件名</th>
                <th>ID</th>
                <th>密码</th>
                <th>浏览/下载</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="sharesTable"></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- USERS -->
    <div id="usersTab" class="tab-content">
      <div class="table-card">
        <div class="table-header">
          <div class="table-title">授权用户列表</div>
          <button class="btn btn-primary" onclick="showAddUserModal()">添加用户</button>
        </div>
        <div style="overflow-x:auto;">
          <table>
            <thead>
              <tr>
                <th>邮箱</th>
                <th>角色</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="usersTable"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <!-- Add User Modal -->
  <div class="modal-overlay" id="addUserModal">
    <div class="modal">
      <div class="modal-title">添加新用户</div>
      <form onsubmit="addUser(event)">
        <div class="form-group">
          <label class="form-label">电子邮箱</label>
          <input type="email" id="newUserEmail" class="form-input" required>
        </div>
        <div class="form-group">
          <label class="form-label">密码</label>
          <input type="text" id="newUserPassword" class="form-input" required>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn btn-text" onclick="closeModal('addUserModal')">取消</button>
          <button type="submit" class="btn btn-primary">添加</button>
        </div>
      </form>
    </div>
  </div>

  <div class="toast-container" id="toastContainer"></div>
  <div class="loading-overlay" id="loadingOverlay" style="display: none;"><div class="spinner"></div></div>

  <script>
    async function checkAdminAuth() {
      try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        if (!data.authenticated || data.role !== 'admin') window.location.href = '/login.html';
      } catch (error) { window.location.href = '/login.html'; }
    }

    function switchTab(tab) {
      document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById(tab + 'Tab').classList.add('active');
      if (tab === 'stats') loadStats();
      else if (tab === 'shares') loadShares();
      else if (tab === 'users') loadUsers();
    }

    async function loadStats() {
      try {
        const res = await fetch('/api/admin/stats');
        const data = await res.json();
        if (data.success) {
          document.getElementById('totalShares').textContent = data.totalShares;
          document.getElementById('totalViews').textContent = data.totalViews;
          document.getElementById('totalDownloads').textContent = data.totalDownloads;
        }
      } catch (e) { showToast('加载统计失败'); }
    }

    async function loadShares() {
      showLoading(true);
      try {
        const res = await fetch('/api/admin/shares');
        const data = await res.json();
        const tbody = document.getElementById('sharesTable');
        if (!data.success) throw new Error(data.message);
        
        if (data.shares.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-sub);">暂无数据</td></tr>';
          return;
        }

        tbody.innerHTML = data.shares.map(s => \`
          <tr>
            <td style="font-weight:500">\${escapeHtml(s.fileName)}</td>
            <td style="font-family:monospace; color:var(--text-sub)">\${s.shareId}</td>
            <td>\${s.passwordHash ? '🔒' : '-'}</td>
            <td>\${s.viewCount} / \${s.downloadCount}</td>
            <td>\${s.isExpired ? '<span class="badge badge-red">已过期</span>' : '<span class="badge badge-green">有效</span>'}</td>
            <td>
              <button class="btn btn-text" style="padding:4px 8px;" onclick="copyShareLink('\${s.shareId}')">复制</button>
              <button class="btn btn-text" style="padding:4px 8px; color:var(--danger)" onclick="deleteShare('\${s.shareId}')">删除</button>
            </td>
          </tr>
        \`).join('');
      } catch (e) { showToast('加载失败: ' + e.message); }
      finally { showLoading(false); }
    }

    async function loadUsers() {
      showLoading(true);
      try {
        const res = await fetch('/api/admin/users');
        const data = await res.json();
        const tbody = document.getElementById('usersTable');
        if (!data.success) throw new Error(data.message);

        if (data.users.length === 0) {
          tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;">暂无用户</td></tr>';
          return;
        }

        tbody.innerHTML = data.users.map(u => \`
          <tr>
            <td style="font-weight:500">\${escapeHtml(u.email)}</td>
            <td>\${u.role==='admin'?'<span class="badge badge-green">管理员</span>':'普通用户'}</td>
            <td style="color:var(--text-sub)">\${u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '-'}</td>
            <td>
              <button class="btn btn-text" style="color:var(--danger)" onclick="deleteUser('\${encodeURIComponent(u.email)}')">删除</button>
            </td>
          </tr>
        \`).join('');
      } catch (e) { showToast(e.message); }
      finally { showLoading(false); }
    }

    async function addUser(e) {
      e.preventDefault();
      const email = document.getElementById('newUserEmail').value;
      const password = document.getElementById('newUserPassword').value;
      closeModal('addUserModal'); showLoading(true);
      
      try {
        const res = await fetch('/api/admin/users', {
          method: 'POST', headers: {'Content-Type':'application/json'},
          body: JSON.stringify({ email, password })
        });
        const data = await res.json();
        if(data.success) { showToast('用户添加成功'); loadUsers(); }
        else showToast(data.message);
      } catch(e) { showToast(e.message); }
      finally { showLoading(false); }
    }

    async function deleteUser(email) {
      if(!confirm('确定要删除此用户吗？')) return;
      showLoading(true);
      try {
        await fetch('/api/admin/users/'+email, { method: 'DELETE' });
        loadUsers(); showToast('已删除');
      } catch(e) { showToast('操作失败'); }
      finally { showLoading(false); }
    }

    async function deleteShare(id) {
      if(!confirm('确定要删除此分享吗？')) return;
      showLoading(true);
      try {
        await fetch('/api/admin/shares/'+id, { method: 'DELETE' });
        loadShares(); showToast('已删除');
      } catch(e) { showToast('操作失败'); }
      finally { showLoading(false); }
    }

    function showAddUserModal() {
      document.getElementById('newUserEmail').value = '';
      document.getElementById('newUserPassword').value = '';
      document.getElementById('addUserModal').classList.add('active');
    }

    function closeModal(id) { document.getElementById(id).classList.remove('active'); }
    function showLoading(show) { document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none'; }
    function showToast(msg) { 
      const b = document.getElementById('toastContainer');
      const d = document.createElement('div'); d.className='toast'; d.innerText=msg;
      b.appendChild(d); setTimeout(()=>d.remove(),3000);
    }
    function copyShareLink(id) {
      navigator.clipboard.writeText(window.location.origin + '/s/' + id);
      showToast('链接已复制');
    }
    function escapeHtml(text) {
      const div = document.createElement('div'); div.textContent = text; return div.innerHTML;
    }
    async function logout() {
      await fetch('/api/logout', { method: 'POST' });
      window.location.href = '/login.html';
    }

    checkAdminAuth();
    loadStats();
  </script>
</body>
</html>
`;

const SHARE_PAGE = `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>文件分享 - EdgeStash</title>
  ${CSS_STYLES}
  <style>
    body { background-color: var(--bg-body); }
    .file-icon-large {
      width: 64px; height: 64px; margin: 0 auto 16px;
      display: flex; align-items: center; justify-content: center;
    }
    .share-meta {
      color: var(--text-sub);
      font-size: 14px;
      margin-bottom: 24px;
    }
    .file-name-large {
      font-size: 22px; color: var(--text-main); margin-bottom: 8px;
      word-break: break-all;
    }
    .download-card {
      text-align: center;
      padding: 40px;
    }
    .error-icon {
      width: 48px; height: 48px; fill: #d93025; margin: 0 auto 16px;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="login-card download-card" id="shareCard">
      <!-- Loading -->
      <div id="loadingState">
        <div class="spinner" style="margin:0 auto 16px;"></div>
        <div style="color:var(--text-sub)">正在加载文件信息...</div>
      </div>
      
      <!-- Error / Expired -->
      <div id="expiredState" style="display: none;">
        <svg class="error-icon" viewBox="0 0 24 24"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm1 15h-2v-2h2v2zm0-4h-2V7h2v6z"/></svg>
        <h2 style="font-size:18px; margin-bottom:8px;">链接无效或已过期</h2>
        <p style="color:var(--text-sub); font-size:14px;">该文件可能已被删除，或者您的访问权限不足。</p>
      </div>
      
      <!-- Content -->
      <div id="shareContent" style="display: none;">
        <div class="file-icon-large">
          <svg viewBox="0 0 24 24" style="width:64px; height:64px; fill:#4285f4"><path d="M6 2c-1.1 0-1.99.9-1.99 2L4 20c0 1.1.89 2 1.99 2H18c1.1 0 2-.9 2-2V8l-6-6H6zm7 7V3.5L18.5 9H13z"/></svg>
        </div>
        <div class="file-name-large" id="fileName">File Name</div>
        <div class="share-meta" id="fileSize">0 KB</div>
        
        <div id="passwordForm" style="display: none; text-align: left; margin-bottom: 20px;">
          <label class="form-label">请输入提取密码</label>
          <input type="password" id="sharePassword" class="form-input" placeholder="密码">
        </div>
        
        <button class="btn btn-primary" style="width: 100%; height: 48px; font-size: 16px;" onclick="downloadFile()">
          下载
        </button>
      </div>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <script>
    let shareId = '';
    let requiresPassword = false;
    
    async function loadShareInfo() {
      const pathParts = window.location.pathname.split('/');
      shareId = pathParts[pathParts.length - 1];
      if (!shareId) return showExpired();
      
      try {
        const res = await fetch('/api/share/' + shareId);
        const data = await res.json();
        
        if (!data.success) return showExpired();
        
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('shareContent').style.display = 'block';
        
        document.getElementById('fileName').textContent = data.fileName;
        document.getElementById('fileSize').textContent = data.fileSizeFormatted;
        
        requiresPassword = data.requiresPassword;
        if (requiresPassword) {
          document.getElementById('passwordForm').style.display = 'block';
        }
      } catch (error) { showExpired(); }
    }
    
    function showExpired() {
      document.getElementById('loadingState').style.display = 'none';
      document.getElementById('expiredState').style.display = 'block';
    }
    
    async function downloadFile() {
      const password = document.getElementById('sharePassword')?.value || '';
      if (requiresPassword && !password) {
        return showToast('请输入密码');
      }
      
      const btn = document.querySelector('.btn-primary');
      const originalText = btn.innerText;
      btn.innerText = '正在请求...';
      btn.disabled = true;

      try {
        const res = await fetch('/api/share/' + shareId + '/download', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        
        if (res.ok) {
          const disposition = res.headers.get('Content-Disposition');
          let filename = document.getElementById('fileName').textContent;
          if (disposition && disposition.match(/filename=/)) {
            // simple parse
          }
          const blob = await res.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filename;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          showToast('开始下载');
        } else {
          const data = await res.json();
          showToast(data.message || '下载失败');
        }
      } catch (e) {
        showToast('下载出错: ' + e.message);
      } finally {
        btn.innerText = originalText;
        btn.disabled = false;
      }
    }
    
    function showToast(msg) {
      const b = document.getElementById('toastContainer');
      const d = document.createElement('div'); d.className='toast'; d.innerText=msg;
      b.appendChild(d); setTimeout(()=>d.remove(),3000);
    }
    
    loadShareInfo();
  </script>
</body>
</html>
`;

// ============================================================================
// MAIN REQUEST HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    
    // CORS headers for API requests
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };
    
    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    
    try {
      // API Routes
      if (path.startsWith('/api/')) {
        // Auth routes
        if (path === '/api/login' && method === 'POST') {
          return await handleLogin(request, env);
        }
        
        if (path === '/api/logout' && method === 'POST') {
          return await handleLogout();
        }
        
        if (path === '/api/auth/check') {
          return await handleCheckAuth(request, env);
        }
        
        // File management routes
        if (path.startsWith('/api/files')) {
          const filePath = path.slice('/api/files'.length) || '/';
          
          if (method === 'GET') {
            return await handleListFiles(request, env, filePath);
          }
          if (method === 'POST') {
            return await handleUploadFile(request, env, filePath);
          }
          if (method === 'PUT') {
            return await handleRenameFile(request, env, filePath);
          }
          if (method === 'DELETE') {
            return await handleDeleteFile(request, env, filePath);
          }
        }
        
        // Folder creation
        if (path === '/api/folders' && method === 'POST') {
          return await handleCreateFolder(request, env);
        }
        
        // Download route
        if (path.startsWith('/api/download')) {
          const filePath = path.slice('/api/download'.length);
          return await handleDownloadFile(request, env, filePath);
        }
        
        // Preview route
        if (path.startsWith('/api/preview')) {
          const filePath = path.slice('/api/preview'.length);
          return await handlePreviewFile(request, env, filePath);
        }
        
        // Share routes
        if (path === '/api/share' && method === 'POST') {
          return await handleCreateShare(request, env);
        }
        
        if (path.match(/^\/api\/share\/[^/]+$/) && method === 'GET') {
          const shareId = path.split('/').pop();
          return await handleGetShareInfo(request, env, shareId);
        }
        
        if (path.match(/^\/api\/share\/[^/]+\/download$/) && method === 'POST') {
          const shareId = path.split('/')[3];
          return await handleShareDownload(request, env, shareId);
        }
        
        // Admin routes
        if (path === '/api/admin/stats' && method === 'GET') {
          return await handleGetStats(request, env);
        }
        
        if (path === '/api/admin/shares' && method === 'GET') {
          return await handleListShares(request, env);
        }
        
        if (path.match(/^\/api\/admin\/shares\/[^/]+$/) && method === 'DELETE') {
          const shareId = path.split('/').pop();
          return await handleDeleteShare(request, env, shareId);
        }
        
        if (path === '/api/admin/users' && method === 'GET') {
          return await handleListUsers(request, env);
        }
        
        if (path === '/api/admin/users' && method === 'POST') {
          return await handleCreateUser(request, env);
        }
        
        if (path.match(/^\/api\/admin\/users\/[^/]+$/) && method === 'DELETE') {
          const email = path.split('/').pop();
          return await handleDeleteUser(request, env, email);
        }
        
        return jsonResponse({ success: false, message: 'API 路径不存在' }, 404);
      }
      
      // Share page route
      if (path.startsWith('/s/')) {
        return htmlResponse(SHARE_PAGE);
      }
      
      // Static page routes
      if (path === '/login.html' || path === '/login') {
        return htmlResponse(LOGIN_PAGE);
      }
      
      if (path === '/admin.html' || path === '/admin') {
        // Check if user is admin
        const auth = await verifyAuth(request, env);
        if (!auth || auth.role !== 'admin') {
          return Response.redirect(url.origin + '/login.html', 302);
        }
        return htmlResponse(ADMIN_PAGE);
      }
      
      // Root and index - check auth
      if (path === '/' || path === '/index.html') {
        const auth = await verifyAuth(request, env);
        if (!auth) {
          return Response.redirect(url.origin + '/login.html', 302);
        }
        return htmlResponse(INDEX_PAGE);
      }
      
      // Default: redirect to root
      return Response.redirect(url.origin + '/', 302);
      
    } catch (error) {
      console.error('Error:', error);
      return jsonResponse({ success: false, message: '服务器错误: ' + error.message }, 500);
    }
  }
};
