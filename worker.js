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

const CSS_STYLES = `
<style>
  * {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
  }
  
  :root {
    --primary: #6366f1;
    --primary-dark: #4f46e5;
    --primary-light: #818cf8;
    --secondary: #8b5cf6;
    --accent: #06b6d4;
    --background: #0f172a;
    --surface: #1e293b;
    --surface-light: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --success: #10b981;
    --warning: #f59e0b;
    --error: #ef4444;
    --gradient: linear-gradient(135deg, #6366f1 0%, #8b5cf6 50%, #06b6d4 100%);
  }
  
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--background);
    color: var(--text);
    min-height: 100vh;
    line-height: 1.6;
  }
  
  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
  }
  
  /* Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 10px 20px;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    text-decoration: none;
  }
  
  .btn-primary {
    background: var(--gradient);
    color: white;
  }
  
  .btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 10px 20px rgba(99, 102, 241, 0.3);
  }
  
  .btn-secondary {
    background: var(--surface-light);
    color: var(--text);
  }
  
  .btn-secondary:hover {
    background: var(--surface);
  }
  
  .btn-danger {
    background: var(--error);
    color: white;
  }
  
  .btn-danger:hover {
    background: #dc2626;
  }
  
  .btn-sm {
    padding: 6px 12px;
    font-size: 12px;
  }
  
  /* Forms */
  .form-group {
    margin-bottom: 20px;
  }
  
  .form-label {
    display: block;
    margin-bottom: 8px;
    font-weight: 500;
    color: var(--text-muted);
  }
  
  .form-input {
    width: 100%;
    padding: 12px 16px;
    background: var(--surface);
    border: 1px solid var(--surface-light);
    border-radius: 8px;
    color: var(--text);
    font-size: 14px;
    transition: all 0.2s ease;
  }
  
  .form-input:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.2);
  }
  
  .form-select {
    width: 100%;
    padding: 12px 16px;
    background: var(--surface);
    border: 1px solid var(--surface-light);
    border-radius: 8px;
    color: var(--text);
    font-size: 14px;
    cursor: pointer;
  }
  
  /* Cards */
  .card {
    background: var(--surface);
    border-radius: 16px;
    padding: 24px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  }
  
  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
  }
  
  .card-title {
    font-size: 18px;
    font-weight: 600;
  }
  
  /* Tables */
  .table-container {
    overflow-x: auto;
  }
  
  table {
    width: 100%;
    border-collapse: collapse;
  }
  
  th, td {
    padding: 12px 16px;
    text-align: left;
    border-bottom: 1px solid var(--surface-light);
  }
  
  th {
    font-weight: 600;
    color: var(--text-muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  
  tr:hover {
    background: var(--surface-light);
  }
  
  /* Modal */
  .modal-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.7);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    opacity: 0;
    visibility: hidden;
    transition: all 0.3s ease;
  }
  
  .modal-overlay.active {
    opacity: 1;
    visibility: visible;
  }
  
  .modal {
    background: var(--surface);
    border-radius: 16px;
    padding: 24px;
    width: 90%;
    max-width: 500px;
    transform: scale(0.9);
    transition: all 0.3s ease;
    max-height: 90vh;
    overflow-y: auto;
  }
  
  .modal-overlay.active .modal {
    transform: scale(1);
  }
  
  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 20px;
  }
  
  .modal-title {
    font-size: 20px;
    font-weight: 600;
  }
  
  .modal-close {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 24px;
    cursor: pointer;
    padding: 0;
    line-height: 1;
  }
  
  .modal-close:hover {
    color: var(--text);
  }
  
  /* Preview Modal - Full Screen */
  .preview-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.95);
    display: flex;
    flex-direction: column;
    z-index: 2000;
    opacity: 0;
    visibility: hidden;
    transition: all 0.3s ease;
  }
  
  .preview-overlay.active {
    opacity: 1;
    visibility: visible;
  }
  
  .preview-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 24px;
    background: var(--surface);
    border-bottom: 1px solid var(--surface-light);
  }
  
  .preview-filename {
    font-weight: 600;
    color: var(--text);
  }
  
  .preview-actions {
    display: flex;
    gap: 12px;
  }
  
  .preview-content {
    flex: 1;
    overflow: auto;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  
  .preview-image {
    max-width: 100%;
    max-height: 100%;
    object-fit: contain;
  }
  
  .preview-text {
    width: 100%;
    height: 100%;
    background: var(--surface);
    border-radius: 8px;
    padding: 20px;
    overflow: auto;
    font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
    font-size: 14px;
    line-height: 1.6;
    white-space: pre-wrap;
    word-wrap: break-word;
  }
  
  .preview-pdf {
    width: 100%;
    height: 100%;
    border: none;
    border-radius: 8px;
  }
  
  .preview-video, .preview-audio {
    max-width: 100%;
    max-height: 100%;
  }
  
  .preview-markdown {
    width: 100%;
    max-width: 900px;
    height: 100%;
    background: var(--surface);
    border-radius: 8px;
    padding: 40px;
    overflow: auto;
    line-height: 1.8;
  }
  
  .preview-markdown h1, .preview-markdown h2, .preview-markdown h3 {
    margin-top: 24px;
    margin-bottom: 16px;
    color: var(--text);
  }
  
  .preview-markdown p {
    margin-bottom: 16px;
  }
  
  .preview-markdown code {
    background: var(--background);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: 'Monaco', 'Menlo', monospace;
  }
  
  .preview-markdown pre {
    background: var(--background);
    padding: 16px;
    border-radius: 8px;
    overflow-x: auto;
    margin-bottom: 16px;
  }
  
  .preview-markdown pre code {
    background: none;
    padding: 0;
  }
  
  .preview-markdown blockquote {
    border-left: 4px solid var(--primary);
    padding-left: 16px;
    margin: 16px 0;
    color: var(--text-muted);
  }
  
  .preview-markdown ul, .preview-markdown ol {
    margin-bottom: 16px;
    padding-left: 24px;
  }
  
  .preview-markdown li {
    margin-bottom: 8px;
  }
  
  .preview-markdown a {
    color: var(--primary);
  }
  
  .preview-markdown img {
    max-width: 100%;
    border-radius: 8px;
  }
  
  .preview-markdown table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 16px;
  }
  
  .preview-markdown th, .preview-markdown td {
    border: 1px solid var(--surface-light);
    padding: 8px 12px;
  }
  
  .preview-office {
    width: 100%;
    height: 100%;
    background: white;
    border-radius: 8px;
  }
  
  .preview-loading {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    color: var(--text-muted);
  }
  
  .preview-error {
    text-align: center;
    color: var(--error);
  }
  
  /* Toast */
  .toast-container {
    position: fixed;
    top: 20px;
    right: 20px;
    z-index: 3000;
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  
  .toast {
    padding: 16px 20px;
    border-radius: 8px;
    color: white;
    font-weight: 500;
    animation: slideIn 0.3s ease;
    display: flex;
    align-items: center;
    gap: 10px;
    min-width: 300px;
  }
  
  .toast-success {
    background: var(--success);
  }
  
  .toast-error {
    background: var(--error);
  }
  
  .toast-info {
    background: var(--primary);
  }
  
  @keyframes slideIn {
    from {
      transform: translateX(100%);
      opacity: 0;
    }
    to {
      transform: translateX(0);
      opacity: 1;
    }
  }
  
  /* Header */
  .header {
    background: var(--surface);
    padding: 16px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    border-bottom: 1px solid var(--surface-light);
  }
  
  .logo {
    font-size: 24px;
    font-weight: 700;
    background: var(--gradient);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  
  .header-actions {
    display: flex;
    gap: 12px;
  }
  
  /* Breadcrumb */
  .breadcrumb {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 16px 0;
    flex-wrap: wrap;
  }
  
  .breadcrumb-item {
    color: var(--text-muted);
    text-decoration: none;
    transition: color 0.2s;
  }
  
  .breadcrumb-item:hover {
    color: var(--primary);
  }
  
  .breadcrumb-item.active {
    color: var(--text);
  }
  
  .breadcrumb-separator {
    color: var(--text-muted);
  }
  
  /* File List */
  .file-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 16px;
  }
  
  .file-item {
    background: var(--surface);
    border-radius: 12px;
    padding: 16px;
    cursor: pointer;
    transition: all 0.2s ease;
    border: 1px solid transparent;
  }
  
  .file-item:hover {
    border-color: var(--primary);
    transform: translateY(-2px);
  }
  
  .file-icon {
    font-size: 48px;
    margin-bottom: 12px;
    text-align: center;
  }
  
  .file-name {
    font-weight: 500;
    text-align: center;
    word-break: break-all;
    margin-bottom: 4px;
  }
  
  .file-meta {
    font-size: 12px;
    color: var(--text-muted);
    text-align: center;
  }
  
  .file-actions {
    display: flex;
    gap: 8px;
    margin-top: 12px;
    justify-content: center;
    flex-wrap: wrap;
  }
  
  /* Stats Cards */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 20px;
    margin-bottom: 30px;
  }
  
  .stat-card {
    background: var(--surface);
    border-radius: 16px;
    padding: 24px;
    text-align: center;
  }
  
  .stat-value {
    font-size: 36px;
    font-weight: 700;
    background: var(--gradient);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  
  .stat-label {
    color: var(--text-muted);
    font-size: 14px;
    margin-top: 8px;
  }
  
  /* Tabs */
  .tabs {
    display: flex;
    gap: 4px;
    background: var(--surface);
    padding: 4px;
    border-radius: 12px;
    margin-bottom: 24px;
  }
  
  .tab {
    flex: 1;
    padding: 12px 20px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border-radius: 8px;
    transition: all 0.2s ease;
  }
  
  .tab.active {
    background: var(--primary);
    color: white;
  }
  
  .tab:hover:not(.active) {
    color: var(--text);
  }
  
  .tab-content {
    display: none;
  }
  
  .tab-content.active {
    display: block;
  }
  
  /* Badge */
  .badge {
    display: inline-block;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 500;
  }
  
  .badge-success {
    background: rgba(16, 185, 129, 0.2);
    color: var(--success);
  }
  
  .badge-warning {
    background: rgba(245, 158, 11, 0.2);
    color: var(--warning);
  }
  
  .badge-error {
    background: rgba(239, 68, 68, 0.2);
    color: var(--error);
  }
  
  .badge-info {
    background: rgba(99, 102, 241, 0.2);
    color: var(--primary);
  }
  
  /* Login Page */
  .login-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--background);
    padding: 20px;
  }
  
  .login-card {
    background: var(--surface);
    border-radius: 24px;
    padding: 40px;
    width: 100%;
    max-width: 420px;
    box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
  }
  
  .login-header {
    text-align: center;
    margin-bottom: 32px;
  }
  
  .login-logo {
    font-size: 32px;
    font-weight: 700;
    background: var(--gradient);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 8px;
  }
  
  .login-subtitle {
    color: var(--text-muted);
  }
  
  .login-tabs {
    display: flex;
    gap: 4px;
    background: var(--background);
    padding: 4px;
    border-radius: 12px;
    margin-bottom: 24px;
  }
  
  .login-tab {
    flex: 1;
    padding: 12px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    border-radius: 8px;
    transition: all 0.2s ease;
  }
  
  .login-tab.active {
    background: var(--primary);
    color: white;
  }
  
  /* Share Page */
  .share-container {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--background);
    padding: 20px;
  }
  
  .share-card {
    background: var(--surface);
    border-radius: 24px;
    padding: 40px;
    width: 100%;
    max-width: 480px;
    text-align: center;
  }
  
  .share-icon {
    font-size: 64px;
    margin-bottom: 20px;
  }
  
  .share-filename {
    font-size: 20px;
    font-weight: 600;
    margin-bottom: 8px;
    word-break: break-all;
  }
  
  .share-filesize {
    color: var(--text-muted);
    margin-bottom: 24px;
  }
  
  .share-expired {
    color: var(--error);
    font-size: 18px;
  }
  
  /* Empty State */
  .empty-state {
    text-align: center;
    padding: 60px 20px;
    color: var(--text-muted);
  }
  
  .empty-icon {
    font-size: 64px;
    margin-bottom: 16px;
    opacity: 0.5;
  }
  
  /* Responsive */
  @media (max-width: 768px) {
    .header {
      flex-direction: column;
      gap: 16px;
    }
    
    .header-actions {
      width: 100%;
      justify-content: center;
    }
    
    .file-grid {
      grid-template-columns: repeat(auto-fill, minmax(150px, 1fr));
    }
    
    .stats-grid {
      grid-template-columns: 1fr;
    }
    
    .tabs {
      flex-direction: column;
    }
    
    .preview-header {
      flex-direction: column;
      gap: 12px;
    }
  }
  
  /* Loading Spinner */
  .spinner {
    width: 40px;
    height: 40px;
    border: 3px solid var(--surface-light);
    border-top-color: var(--primary);
    border-radius: 50%;
    animation: spin 1s linear infinite;
  }
  
  @keyframes spin {
    to {
      transform: rotate(360deg);
    }
  }
  
  .loading-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(15, 23, 42, 0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 3000;
  }
  
  /* Context Menu */
  .context-menu {
    position: fixed;
    background: var(--surface);
    border-radius: 8px;
    padding: 8px 0;
    min-width: 160px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
    z-index: 1500;
    display: none;
  }
  
  .context-menu.active {
    display: block;
  }
  
  .context-menu-item {
    padding: 10px 16px;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 10px;
    transition: background 0.2s;
  }
  
  .context-menu-item:hover {
    background: var(--surface-light);
  }
  
  .context-menu-item.danger {
    color: var(--error);
  }
  
  /* Toolbar */
  .toolbar {
    display: flex;
    gap: 12px;
    margin-bottom: 20px;
    flex-wrap: wrap;
  }
  
  /* Upload Area */
  .upload-area {
    border: 2px dashed var(--surface-light);
    border-radius: 12px;
    padding: 40px;
    text-align: center;
    cursor: pointer;
    transition: all 0.2s ease;
  }
  
  .upload-area:hover, .upload-area.dragover {
    border-color: var(--primary);
    background: rgba(99, 102, 241, 0.1);
  }
  
  .upload-area input {
    display: none;
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
      <div class="login-header">
        <div class="login-logo">EdgeStash</div>
        <div class="login-subtitle">基于 Cloudflare 的云盘服务</div>
      </div>
      
      <div class="login-tabs">
        <button class="login-tab active" onclick="switchLoginTab('admin')">管理员登录</button>
        <button class="login-tab" onclick="switchLoginTab('user')">用户登录</button>
      </div>
      
      <form id="loginForm" onsubmit="handleLogin(event)">
        <div id="emailField" class="form-group" style="display: none;">
          <label class="form-label">邮箱</label>
          <input type="email" id="email" class="form-input" placeholder="请输入邮箱">
        </div>
        
        <div class="form-group">
          <label class="form-label">密码</label>
          <input type="password" id="password" class="form-input" placeholder="请输入密码" required>
        </div>
        
        <button type="submit" class="btn btn-primary" style="width: 100%;">
          登录
        </button>
      </form>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <script>
    let isAdminLogin = true;
    
    function switchLoginTab(type) {
      isAdminLogin = type === 'admin';
      document.querySelectorAll('.login-tab').forEach((tab, index) => {
        tab.classList.toggle('active', (index === 0 && isAdminLogin) || (index === 1 && !isAdminLogin));
      });
      document.getElementById('emailField').style.display = isAdminLogin ? 'none' : 'block';
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
          showToast('登录成功', 'success');
          setTimeout(() => {
            window.location.href = '/';
          }, 500);
        } else {
          showToast(data.message || '登录失败', 'error');
        }
      } catch (error) {
        showToast('登录失败: ' + error.message, 'error');
      }
    }
    
    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      container.appendChild(toast);
      
      setTimeout(() => {
        toast.remove();
      }, 3000);
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
  <title>EdgeStash - 云盘</title>
  ${CSS_STYLES}
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/mammoth@1.6.0/mammoth.browser.min.js"></script>
</head>
<body>
  <div class="header">
    <div class="logo">EdgeStash</div>
    <div class="header-actions">
      <button class="btn btn-secondary" onclick="window.location.href='/admin.html'">管理后台</button>
      <button class="btn btn-secondary" onclick="logout()">退出登录</button>
    </div>
  </div>
  
  <div class="container">
    <div class="breadcrumb" id="breadcrumb"></div>
    
    <div class="toolbar">
      <button class="btn btn-primary" onclick="showNewFolderModal()">
        📁 新建文件夹
      </button>
      <button class="btn btn-primary" onclick="document.getElementById('fileInput').click()">
        📤 上传文件
      </button>
      <input type="file" id="fileInput" multiple style="display: none;" onchange="handleFileUpload(event)">
    </div>
    
    <div class="card">
      <div id="fileList" class="file-grid"></div>
      <div id="emptyState" class="empty-state" style="display: none;">
        <div class="empty-icon">📂</div>
        <div>此文件夹为空</div>
      </div>
    </div>
  </div>
  
  <!-- New Folder Modal -->
  <div class="modal-overlay" id="newFolderModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">新建文件夹</div>
        <button class="modal-close" onclick="closeModal('newFolderModal')">&times;</button>
      </div>
      <form onsubmit="createFolder(event)">
        <div class="form-group">
          <label class="form-label">文件夹名称</label>
          <input type="text" id="folderName" class="form-input" placeholder="请输入文件夹名称" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">创建</button>
      </form>
    </div>
  </div>
  
  <!-- Rename Modal -->
  <div class="modal-overlay" id="renameModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">重命名</div>
        <button class="modal-close" onclick="closeModal('renameModal')">&times;</button>
      </div>
      <form onsubmit="renameFile(event)">
        <div class="form-group">
          <label class="form-label">新名称</label>
          <input type="text" id="newFileName" class="form-input" required>
        </div>
        <input type="hidden" id="renameFilePath">
        <button type="submit" class="btn btn-primary" style="width: 100%;">确认</button>
      </form>
    </div>
  </div>
  
  <!-- Share Modal -->
  <div class="modal-overlay" id="shareModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">创建分享链接</div>
        <button class="modal-close" onclick="closeModal('shareModal')">&times;</button>
      </div>
      <form onsubmit="createShare(event)">
        <div class="form-group">
          <label class="form-label">分享密码（留空则无密码）</label>
          <input type="text" id="sharePassword" class="form-input" placeholder="可选">
        </div>
        <div class="form-group">
          <label class="form-label">有效期</label>
          <select id="shareExpiry" class="form-select">
            <option value="1h">1小时</option>
            <option value="1d" selected>1天</option>
            <option value="1m">1个月</option>
            <option value="permanent">永久有效</option>
          </select>
        </div>
        <input type="hidden" id="shareFilePath">
        <button type="submit" class="btn btn-primary" style="width: 100%;">创建分享链接</button>
      </form>
    </div>
  </div>
  
  <!-- Share Result Modal -->
  <div class="modal-overlay" id="shareResultModal">
    <div class="modal">
      <div class="modal-header">
        <div class="modal-title">分享链接已创建</div>
        <button class="modal-close" onclick="closeModal('shareResultModal')">&times;</button>
      </div>
      <div class="form-group">
        <label class="form-label">分享链接</label>
        <input type="text" id="shareResultUrl" class="form-input" readonly>
      </div>
      <button class="btn btn-primary" style="width: 100%;" onclick="copyShareLink()">复制链接</button>
    </div>
  </div>
  
  <!-- Preview Modal -->
  <div class="preview-overlay" id="previewOverlay">
    <div class="preview-header">
      <div class="preview-filename" id="previewFilename"></div>
      <div class="preview-actions">
        <button class="btn btn-primary" id="previewDownloadBtn">下载</button>
        <button class="btn btn-secondary" onclick="closePreview()">关闭</button>
      </div>
    </div>
    <div class="preview-content" id="previewContent">
      <div class="preview-loading">
        <div class="spinner"></div>
        <div>加载中...</div>
      </div>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <div class="loading-overlay" id="loadingOverlay" style="display: none;">
    <div class="spinner"></div>
  </div>
  
  <script>
    let currentPath = '/';
    
    async function checkAuth() {
      try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        if (!data.authenticated) {
          window.location.href = '/login.html';
        }
      } catch (error) {
        window.location.href = '/login.html';
      }
    }
    
    async function loadFiles() {
      showLoading(true);
      try {
        const response = await fetch('/api/files' + currentPath);
        const data = await response.json();
        
        if (!data.success) {
          if (response.status === 401) {
            window.location.href = '/login.html';
            return;
          }
          throw new Error(data.message);
        }
        
        renderBreadcrumb();
        renderFiles(data.folders, data.files);
      } catch (error) {
        showToast('加载文件失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function renderBreadcrumb() {
      const breadcrumb = document.getElementById('breadcrumb');
      const parts = currentPath.split('/').filter(p => p);
      
      let html = '<a href="#" class="breadcrumb-item" onclick="navigateTo(\\'/\\')">🏠 根目录</a>';
      
      let path = '';
      parts.forEach((part, index) => {
        path += '/' + part;
        const isLast = index === parts.length - 1;
        html += '<span class="breadcrumb-separator">/</span>';
        if (isLast) {
          html += '<span class="breadcrumb-item active">' + part + '</span>';
        } else {
          html += '<a href="#" class="breadcrumb-item" onclick="navigateTo(\\'' + path + '\\')">' + part + '</a>';
        }
      });
      
      breadcrumb.innerHTML = html;
    }
    
    function renderFiles(folders, files) {
      const fileList = document.getElementById('fileList');
      const emptyState = document.getElementById('emptyState');
      
      if (folders.length === 0 && files.length === 0) {
        fileList.innerHTML = '';
        emptyState.style.display = 'block';
        return;
      }
      
      emptyState.style.display = 'none';
      
      let html = '';
      
      // Render folders
      folders.forEach(folder => {
        html += \`
          <div class="file-item" ondblclick="navigateTo('\${folder.path}')">
            <div class="file-icon">📁</div>
            <div class="file-name">\${escapeHtml(folder.name)}</div>
            <div class="file-meta">文件夹</div>
            <div class="file-actions">
              <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showRenameModal('\${folder.path}', '\${escapeHtml(folder.name)}')">重命名</button>
              <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteFile('\${folder.path}')">删除</button>
            </div>
          </div>
        \`;
      });
      
      // Render files
      files.forEach(file => {
        const icon = getFileIcon(file.name);
        const previewable = file.previewType ? 'true' : 'false';
        const previewType = file.previewType || '';
        html += \`
          <div class="file-item" ondblclick="handleFileClick('\${file.path}', '\${previewType}', '\${escapeHtml(file.name)}')" data-previewable="\${previewable}">
            <div class="file-icon">\${icon}</div>
            <div class="file-name">\${escapeHtml(file.name)}</div>
            <div class="file-meta">\${file.sizeFormatted}\${previewType ? ' <span class="badge badge-info">可预览</span>' : ''}</div>
            <div class="file-actions">
              \${previewType ? '<button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); previewFile(\\'' + file.path + '\\', \\'' + previewType + '\\', \\'' + escapeHtml(file.name) + '\\')">预览</button>' : ''}
              <button class="btn btn-sm btn-primary" onclick="event.stopPropagation(); downloadFile('\${file.path}')">下载</button>
              <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showShareModal('\${file.path}')">分享</button>
              <button class="btn btn-sm btn-secondary" onclick="event.stopPropagation(); showRenameModal('\${file.path}', '\${escapeHtml(file.name)}')">重命名</button>
              <button class="btn btn-sm btn-danger" onclick="event.stopPropagation(); deleteFile('\${file.path}')">删除</button>
            </div>
          </div>
        \`;
      });
      
      fileList.innerHTML = html;
    }
    
    function handleFileClick(path, previewType, filename) {
      if (previewType) {
        previewFile(path, previewType, filename);
      } else {
        downloadFile(path);
      }
    }
    
    function getFileIcon(filename) {
      const ext = filename.split('.').pop().toLowerCase();
      const icons = {
        'pdf': '📕',
        'doc': '📘', 'docx': '📘',
        'xls': '📗', 'xlsx': '📗',
        'ppt': '📙', 'pptx': '📙',
        'jpg': '🖼️', 'jpeg': '🖼️', 'png': '🖼️', 'gif': '🖼️', 'svg': '🖼️', 'webp': '🖼️',
        'mp3': '🎵', 'wav': '🎵', 'flac': '🎵',
        'mp4': '🎬', 'avi': '🎬', 'mkv': '🎬', 'mov': '🎬',
        'zip': '📦', 'rar': '📦', '7z': '📦', 'tar': '📦', 'gz': '📦',
        'js': '📜', 'ts': '📜', 'py': '📜', 'java': '📜', 'cpp': '📜', 'c': '📜',
        'html': '🌐', 'css': '🎨', 'json': '📋',
        'txt': '📄', 'md': '📝'
      };
      return icons[ext] || '📄';
    }
    
    function navigateTo(path) {
      currentPath = path;
      loadFiles();
    }
    
    // ========== Preview Functions ==========
    
    async function previewFile(path, previewType, filename) {
      const overlay = document.getElementById('previewOverlay');
      const content = document.getElementById('previewContent');
      const filenameEl = document.getElementById('previewFilename');
      const downloadBtn = document.getElementById('previewDownloadBtn');
      
      filenameEl.textContent = filename;
      downloadBtn.onclick = () => downloadFile(path);
      
      // Show loading
      content.innerHTML = '<div class="preview-loading"><div class="spinner"></div><div>加载中...</div></div>';
      overlay.classList.add('active');
      
      try {
        const previewUrl = '/api/preview' + path;
        
        switch (previewType) {
          case 'image':
            content.innerHTML = '<img class="preview-image" src="' + previewUrl + '" alt="' + escapeHtml(filename) + '">';
            break;
            
          case 'pdf':
            content.innerHTML = '<iframe class="preview-pdf" src="' + previewUrl + '"></iframe>';
            break;
            
          case 'text':
            const textResponse = await fetch(previewUrl);
            const text = await textResponse.text();
            const ext = filename.split('.').pop().toLowerCase();
            
            if (ext === 'md') {
              // Render Markdown
              const htmlContent = marked.parse(text);
              content.innerHTML = '<div class="preview-markdown">' + htmlContent + '</div>';
            } else if (ext === 'json') {
              // Pretty print JSON
              try {
                const json = JSON.parse(text);
                content.innerHTML = '<pre class="preview-text">' + escapeHtml(JSON.stringify(json, null, 2)) + '</pre>';
              } catch {
                content.innerHTML = '<pre class="preview-text">' + escapeHtml(text) + '</pre>';
              }
            } else {
              content.innerHTML = '<pre class="preview-text">' + escapeHtml(text) + '</pre>';
            }
            break;
            
          case 'video':
            content.innerHTML = '<video class="preview-video" controls autoplay><source src="' + previewUrl + '"></video>';
            break;
            
          case 'audio':
            content.innerHTML = '<audio class="preview-audio" controls autoplay><source src="' + previewUrl + '"></audio>';
            break;
            
          case 'word':
            // Use Mammoth.js to convert docx to HTML
            const docxResponse = await fetch(previewUrl);
            const docxArrayBuffer = await docxResponse.arrayBuffer();
            const result = await mammoth.convertToHtml({ arrayBuffer: docxArrayBuffer });
            content.innerHTML = '<div class="preview-markdown">' + result.value + '</div>';
            break;
            
          default:
            content.innerHTML = '<div class="preview-error">不支持预览此文件类型</div>';
        }
      } catch (error) {
        content.innerHTML = '<div class="preview-error">预览加载失败: ' + escapeHtml(error.message) + '</div>';
      }
    }
    
    function closePreview() {
      const overlay = document.getElementById('previewOverlay');
      overlay.classList.remove('active');
      // Clear content to stop any playing media
      document.getElementById('previewContent').innerHTML = '';
    }
    
    // Close preview on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closePreview();
      }
    });
    
    // ========== File Operations ==========
    
    async function handleFileUpload(event) {
      const files = event.target.files;
      if (!files.length) return;
      
      showLoading(true);
      
      for (const file of files) {
        try {
          const formData = new FormData();
          formData.append('file', file);
          
          const response = await fetch('/api/files' + currentPath, {
            method: 'POST',
            body: formData
          });
          
          const data = await response.json();
          
          if (data.success) {
            showToast('文件 ' + file.name + ' 上传成功', 'success');
          } else {
            showToast('文件 ' + file.name + ' 上传失败: ' + data.message, 'error');
          }
        } catch (error) {
          showToast('文件 ' + file.name + ' 上传失败: ' + error.message, 'error');
        }
      }
      
      event.target.value = '';
      loadFiles();
    }
    
    function showNewFolderModal() {
      document.getElementById('folderName').value = '';
      document.getElementById('newFolderModal').classList.add('active');
    }
    
    async function createFolder(event) {
      event.preventDefault();
      const name = document.getElementById('folderName').value.trim();
      
      if (!name) {
        showToast('请输入文件夹名称', 'error');
        return;
      }
      
      showLoading(true);
      closeModal('newFolderModal');
      
      try {
        let folderPath = currentPath;
        if (!folderPath.endsWith('/')) folderPath += '/';
        folderPath += name;
        
        const response = await fetch('/api/folders', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: folderPath })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('文件夹创建成功', 'success');
          loadFiles();
        } else {
          showToast('创建失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('创建失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function showRenameModal(path, currentName) {
      document.getElementById('renameFilePath').value = path;
      document.getElementById('newFileName').value = currentName;
      document.getElementById('renameModal').classList.add('active');
    }
    
    async function renameFile(event) {
      event.preventDefault();
      const path = document.getElementById('renameFilePath').value;
      const newName = document.getElementById('newFileName').value.trim();
      
      if (!newName) {
        showToast('请输入新名称', 'error');
        return;
      }
      
      showLoading(true);
      closeModal('renameModal');
      
      try {
        const response = await fetch('/api/files' + path, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ newName })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('重命名成功', 'success');
          loadFiles();
        } else {
          showToast('重命名失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('重命名失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function deleteFile(path) {
      if (!confirm('确定要删除吗？此操作不可恢复。')) return;
      
      showLoading(true);
      
      try {
        const response = await fetch('/api/files' + path, {
          method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('删除成功', 'success');
          loadFiles();
        } else {
          showToast('删除失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('删除失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function downloadFile(path) {
      window.open('/api/download' + path, '_blank');
    }
    
    function showShareModal(path) {
      document.getElementById('shareFilePath').value = path;
      document.getElementById('sharePassword').value = '';
      document.getElementById('shareExpiry').value = '1d';
      document.getElementById('shareModal').classList.add('active');
    }
    
    async function createShare(event) {
      event.preventDefault();
      const filePath = document.getElementById('shareFilePath').value;
      const password = document.getElementById('sharePassword').value;
      const expiresIn = document.getElementById('shareExpiry').value;
      
      showLoading(true);
      closeModal('shareModal');
      
      try {
        const response = await fetch('/api/share', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ filePath, password, expiresIn })
        });
        
        const data = await response.json();
        
        if (data.success) {
          const fullUrl = window.location.origin + data.shareUrl;
          document.getElementById('shareResultUrl').value = fullUrl;
          document.getElementById('shareResultModal').classList.add('active');
        } else {
          showToast('创建分享链接失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('创建分享链接失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function copyShareLink() {
      const input = document.getElementById('shareResultUrl');
      input.select();
      document.execCommand('copy');
      showToast('链接已复制到剪贴板', 'success');
    }
    
    async function logout() {
      try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login.html';
      } catch (error) {
        window.location.href = '/login.html';
      }
    }
    
    function closeModal(id) {
      document.getElementById(id).classList.remove('active');
    }
    
    function showLoading(show) {
      document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none';
    }
    
    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      container.appendChild(toast);
      
      setTimeout(() => {
        toast.remove();
      }, 3000);
    }
    
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
    
    // Initialize
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
  <title>管理后台 - EdgeStash</title>
  ${CSS_STYLES}
</head>
<body>
  <div class="header">
    <div class="logo">EdgeStash 管理后台</div>
    <div class="header-actions">
      <button class="btn btn-secondary" onclick="window.location.href='/'">返回云盘</button>
      <button class="btn btn-secondary" onclick="logout()">退出登录</button>
    </div>
  </div>
  
  <div class="container">
    <div class="tabs">
      <button class="tab active" onclick="switchTab('stats')">统计数据</button>
      <button class="tab" onclick="switchTab('shares')">分享链接</button>
      <button class="tab" onclick="switchTab('users')">授权用户</button>
    </div>
    
    <!-- Stats Tab -->
    <div id="statsTab" class="tab-content active">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value" id="totalShares">0</div>
          <div class="stat-label">总分享链接数</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" id="totalViews">0</div>
          <div class="stat-label">总浏览次数</div>
        </div>
        <div class="stat-card">
          <div class="stat-value" id="totalDownloads">0</div>
          <div class="stat-label">总下载次数</div>
        </div>
      </div>
    </div>
    
    <!-- Shares Tab -->
    <div id="sharesTab" class="tab-content">
      <div class="card">
        <div class="card-header">
          <div class="card-title">分享链接管理</div>
        </div>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>文件名</th>
                <th>分享ID</th>
                <th>密码保护</th>
                <th>浏览次数</th>
                <th>下载次数</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody id="sharesTable"></tbody>
          </table>
        </div>
      </div>
    </div>
    
    <!-- Users Tab -->
    <div id="usersTab" class="tab-content">
      <div class="card">
        <div class="card-header">
          <div class="card-title">授权用户管理</div>
          <button class="btn btn-primary" onclick="showAddUserModal()">添加用户</button>
        </div>
        <div class="table-container">
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
      <div class="modal-header">
        <div class="modal-title">添加授权用户</div>
        <button class="modal-close" onclick="closeModal('addUserModal')">&times;</button>
      </div>
      <form onsubmit="addUser(event)">
        <div class="form-group">
          <label class="form-label">邮箱</label>
          <input type="email" id="newUserEmail" class="form-input" placeholder="请输入邮箱" required>
        </div>
        <div class="form-group">
          <label class="form-label">密码</label>
          <input type="text" id="newUserPassword" class="form-input" placeholder="请输入密码" required>
        </div>
        <button type="submit" class="btn btn-primary" style="width: 100%;">添加用户</button>
      </form>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <div class="loading-overlay" id="loadingOverlay" style="display: none;">
    <div class="spinner"></div>
  </div>
  
  <script>
    async function checkAdminAuth() {
      try {
        const response = await fetch('/api/auth/check');
        const data = await response.json();
        if (!data.authenticated || data.role !== 'admin') {
          window.location.href = '/login.html';
        }
      } catch (error) {
        window.location.href = '/login.html';
      }
    }
    
    function switchTab(tab) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      
      event.target.classList.add('active');
      document.getElementById(tab + 'Tab').classList.add('active');
      
      if (tab === 'stats') loadStats();
      else if (tab === 'shares') loadShares();
      else if (tab === 'users') loadUsers();
    }
    
    async function loadStats() {
      try {
        const response = await fetch('/api/admin/stats');
        const data = await response.json();
        
        if (data.success) {
          document.getElementById('totalShares').textContent = data.totalShares;
          document.getElementById('totalViews').textContent = data.totalViews;
          document.getElementById('totalDownloads').textContent = data.totalDownloads;
        }
      } catch (error) {
        showToast('加载统计数据失败', 'error');
      }
    }
    
    async function loadShares() {
      showLoading(true);
      try {
        const response = await fetch('/api/admin/shares');
        const data = await response.json();
        
        if (data.success) {
          const tbody = document.getElementById('sharesTable');
          
          if (data.shares.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted);">暂无分享链接</td></tr>';
            return;
          }
          
          tbody.innerHTML = data.shares.map(share => \`
            <tr>
              <td>\${escapeHtml(share.fileName)}</td>
              <td><code>\${share.shareId}</code></td>
              <td>\${share.passwordHash ? '是' : '否'}</td>
              <td>\${share.viewCount}</td>
              <td>\${share.downloadCount}</td>
              <td>
                \${share.isExpired 
                  ? '<span class="badge badge-error">已过期</span>' 
                  : '<span class="badge badge-success">有效</span>'}
              </td>
              <td>
                <button class="btn btn-sm btn-secondary" onclick="copyShareLink('\${share.shareId}')">复制链接</button>
                <button class="btn btn-sm btn-danger" onclick="deleteShare('\${share.shareId}')">删除</button>
              </td>
            </tr>
          \`).join('');
        }
      } catch (error) {
        showToast('加载分享列表失败', 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function loadUsers() {
      showLoading(true);
      try {
        const response = await fetch('/api/admin/users');
        const data = await response.json();
        
        if (data.success) {
          const tbody = document.getElementById('usersTable');
          
          if (data.users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="text-align: center; color: var(--text-muted);">暂无授权用户</td></tr>';
            return;
          }
          
          tbody.innerHTML = data.users.map(user => \`
            <tr>
              <td>\${escapeHtml(user.email)}</td>
              <td>\${user.role === 'admin' ? '管理员' : '普通用户'}</td>
              <td>\${user.createdAt ? new Date(user.createdAt).toLocaleString() : '-'}</td>
              <td>
                <button class="btn btn-sm btn-danger" onclick="deleteUser('\${encodeURIComponent(user.email)}')">撤销授权</button>
              </td>
            </tr>
          \`).join('');
        }
      } catch (error) {
        showToast('加载用户列表失败', 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function showAddUserModal() {
      document.getElementById('newUserEmail').value = '';
      document.getElementById('newUserPassword').value = '';
      document.getElementById('addUserModal').classList.add('active');
    }
    
    async function addUser(event) {
      event.preventDefault();
      const email = document.getElementById('newUserEmail').value;
      const password = document.getElementById('newUserPassword').value;
      
      showLoading(true);
      closeModal('addUserModal');
      
      try {
        const response = await fetch('/api/admin/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('用户添加成功', 'success');
          loadUsers();
        } else {
          showToast('添加失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('添加失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function deleteUser(email) {
      if (!confirm('确定要撤销该用户的授权吗？')) return;
      
      showLoading(true);
      
      try {
        const response = await fetch('/api/admin/users/' + email, {
          method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('用户已删除', 'success');
          loadUsers();
        } else {
          showToast('删除失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('删除失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    async function deleteShare(shareId) {
      if (!confirm('确定要删除该分享链接吗？')) return;
      
      showLoading(true);
      
      try {
        const response = await fetch('/api/admin/shares/' + shareId, {
          method: 'DELETE'
        });
        
        const data = await response.json();
        
        if (data.success) {
          showToast('分享链接已删除', 'success');
          loadShares();
        } else {
          showToast('删除失败: ' + data.message, 'error');
        }
      } catch (error) {
        showToast('删除失败: ' + error.message, 'error');
      } finally {
        showLoading(false);
      }
    }
    
    function copyShareLink(shareId) {
      const url = window.location.origin + '/s/' + shareId;
      navigator.clipboard.writeText(url).then(() => {
        showToast('链接已复制', 'success');
      }).catch(() => {
        showToast('复制失败', 'error');
      });
    }
    
    async function logout() {
      try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login.html';
      } catch (error) {
        window.location.href = '/login.html';
      }
    }
    
    function closeModal(id) {
      document.getElementById(id).classList.remove('active');
    }
    
    function showLoading(show) {
      document.getElementById('loadingOverlay').style.display = show ? 'flex' : 'none';
    }
    
    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      container.appendChild(toast);
      
      setTimeout(() => {
        toast.remove();
      }, 3000);
    }
    
    function escapeHtml(text) {
      const div = document.createElement('div');
      div.textContent = text;
      return div.innerHTML;
    }
    
    // Initialize
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
</head>
<body>
  <div class="share-container">
    <div class="share-card" id="shareCard">
      <div id="loadingState">
        <div class="spinner" style="margin: 0 auto 20px;"></div>
        <div>加载中...</div>
      </div>
      
      <div id="expiredState" style="display: none;">
        <div class="share-icon">⚠️</div>
        <div class="share-expired">分享链接已过期或不存在</div>
        <p style="color: var(--text-muted); margin-top: 16px;">请联系分享者获取新的链接</p>
      </div>
      
      <div id="shareContent" style="display: none;">
        <div class="share-icon">📄</div>
        <div class="share-filename" id="fileName"></div>
        <div class="share-filesize" id="fileSize"></div>
        
        <div id="passwordForm" style="display: none;">
          <div class="form-group">
            <label class="form-label">请输入分享密码</label>
            <input type="password" id="sharePassword" class="form-input" placeholder="输入密码">
          </div>
        </div>
        
        <button class="btn btn-primary" style="width: 100%; margin-top: 20px;" onclick="downloadFile()">
          下载文件
        </button>
      </div>
    </div>
  </div>
  
  <div class="toast-container" id="toastContainer"></div>
  
  <script>
    let shareId = '';
    let requiresPassword = false;
    
    async function loadShareInfo() {
      // Get share ID from URL
      const pathParts = window.location.pathname.split('/');
      shareId = pathParts[pathParts.length - 1];
      
      if (!shareId) {
        showExpired();
        return;
      }
      
      try {
        const response = await fetch('/api/share/' + shareId);
        const data = await response.json();
        
        if (!data.success) {
          showExpired();
          return;
        }
        
        document.getElementById('loadingState').style.display = 'none';
        document.getElementById('shareContent').style.display = 'block';
        
        document.getElementById('fileName').textContent = data.fileName;
        document.getElementById('fileSize').textContent = data.fileSizeFormatted;
        
        requiresPassword = data.requiresPassword;
        if (requiresPassword) {
          document.getElementById('passwordForm').style.display = 'block';
        }
      } catch (error) {
        showExpired();
      }
    }
    
    function showExpired() {
      document.getElementById('loadingState').style.display = 'none';
      document.getElementById('expiredState').style.display = 'block';
    }
    
    async function downloadFile() {
      const password = document.getElementById('sharePassword')?.value || '';
      
      if (requiresPassword && !password) {
        showToast('请输入分享密码', 'error');
        return;
      }
      
      try {
        const response = await fetch('/api/share/' + shareId + '/download', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password })
        });
        
        if (response.ok) {
          // Get filename from Content-Disposition header
          const contentDisposition = response.headers.get('Content-Disposition');
          let filename = 'download';
          if (contentDisposition) {
            const match = contentDisposition.match(/filename\\*?=(?:UTF-8'')?["']?([^"';\\n]+)/i);
            if (match) {
              filename = decodeURIComponent(match[1]);
            }
          }
          
          // Download the file
          const blob = await response.blob();
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = filename;
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          URL.revokeObjectURL(url);
          
          showToast('下载开始', 'success');
        } else {
          const data = await response.json();
          showToast(data.message || '下载失败', 'error');
        }
      } catch (error) {
        showToast('下载失败: ' + error.message, 'error');
      }
    }
    
    function showToast(message, type = 'info') {
      const container = document.getElementById('toastContainer');
      const toast = document.createElement('div');
      toast.className = 'toast toast-' + type;
      toast.textContent = message;
      container.appendChild(toast);
      
      setTimeout(() => {
        toast.remove();
      }, 3000);
    }
    
    // Initialize
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
