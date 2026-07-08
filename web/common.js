(function () {
    'use strict';

    const STORE_PREFIX = 'nsl_v2_';
    const DB_NAME = 'nginx-shield-lite';
    const DB_VERSION = 1;
    const LOG_STORE = 'log_files';
    const LOG_CACHE_VERSION = 4;

    const BOT_PATTERNS = [
        ['Bingbot', '必应', /bingbot/i],
        ['Googlebot', '谷歌', /googlebot/i],
        ['BaiduSpider', '百度', /baiduspider/i],
        ['DuckDuckBot', 'DuckDuckGo', /duckduckbot/i],
        ['YandexBot', 'Yandex', /yandexbot/i],
        ['SogouSpider', '搜狗', /sogou.*(?:spider|web)/i],
        ['360Spider', '360', /360spider|haosouspider/i],
        ['Bytespider', '字节', /bytespider/i],
        ['PetalBot', '华为花瓣', /petalbot/i],
        ['YisouSpider', '神马', /yisouspider|shenmaspider/i],
        ['OAI-SearchBot', 'OpenAI', /oai-searchbot/i],
        ['ChatGPT-User', 'OpenAI 用户访问', /chatgpt-user/i],
        ['GPTBot', 'OpenAI GPTBot', /\bgptbot\b/i],
        ['Doubao-User', '豆包用户访问', /samanthadoubao|appname\/doubao/i]
    ];

    function load(key, fallback = null) {
        const value = localStorage.getItem(STORE_PREFIX + key);
        return value === null ? fallback : value;
    }

    function save(key, value) {
        localStorage.setItem(STORE_PREFIX + key, value);
    }

    function detectedBasePath() {
        let path = location.pathname || '/';
        path = path.replace(/\/(?:blocked|444|index\.html)\/?$/i, '');
        path = path.replace(/\/+$/, '');
        return path === '/' ? '' : path;
    }

    function apiBase() {
        const stored = load('api_base', null);
        const value = stored === null ? detectedBasePath() : stored;
        return (value || '').trim().replace(/\/+$/, '');
    }

    function apiUrl(path) {
        const normalized = path.startsWith('/') ? path : '/' + path;
        return apiBase() + normalized;
    }

    function configureApiInput(input) {
        const stored = load('api_base', null);
        if (stored === null || (stored === '' && detectedBasePath())) {
            save('api_base', detectedBasePath());
        }
        input.value = load('api_base', '');
        input.addEventListener('change', () => {
            save('api_base', input.value.trim());
            location.reload();
        });
    }

    async function loadDlcNavigation() {
        const nav = document.querySelector('[data-nsl-nav]');
        if (!nav) return;
        try {
            const response = await fetch(apiUrl('/api/dlc'), {cache: 'no-store'});
            if (!response.ok) return;
            const data = await response.json();
            const current = (location.pathname || '/').replace(/\/+$/, '');
            for (const plugin of data.plugins || []) {
                if (!plugin.nav || !plugin.nav.path || !plugin.nav.label) continue;
                const href = apiUrl(plugin.nav.path);
                const anchor = document.createElement('a');
                anchor.href = href;
                anchor.textContent = plugin.nav.label;
                if (current.endsWith(plugin.nav.path)) anchor.className = 'active';
                nav.appendChild(anchor);
            }
        } catch (_) {
            // Navigation enhancement must never prevent the core UI from loading.
        }
    }

    function configCacheKey(name) {
        return 'config_' + encodeURIComponent(apiBase() || 'same-origin') + '_' + name;
    }

    async function fetchConfig(name, force = false) {
        const key = configCacheKey(name);
        let cached = null;
        try {
            cached = JSON.parse(load(key, 'null'));
        } catch (_) {
            cached = null;
        }
        const headers = {};
        if (!force && cached && cached.etag) headers['If-None-Match'] = cached.etag;
        const response = await fetch(apiUrl('/api/config?name=' + encodeURIComponent(name)), {
            headers,
            cache: 'no-store'
        });
        if (response.status === 304 && cached) {
            return {content: cached.content || '', etag: cached.etag, cached: true};
        }
        if (!response.ok) throw new Error('名单加载失败：HTTP ' + response.status);
        const data = await response.json();
        if (data.error) throw new Error(data.error);
        const item = {
            content: data.content || '',
            etag: response.headers.get('ETag') || data.etag || '',
            savedAt: Date.now()
        };
        try {
            save(key, JSON.stringify(item));
        } catch (_) {
            // localStorage may be disabled or full; the live response still works.
        }
        return {content: item.content, etag: item.etag, cached: false};
    }

    async function saveConfig(name, content) {
        const response = await fetch(apiUrl('/api/config?name=' + encodeURIComponent(name)), {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({content})
        });
        const data = await response.json();
        if (!response.ok || !data.ok) throw new Error(data.error || '保存失败');
        const item = {content, etag: data.etag || '', savedAt: Date.now()};
        try {
            save(configCacheKey(name), JSON.stringify(item));
        } catch (_) {}
        return item;
    }

    function openDb() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            request.onupgradeneeded = () => {
                const db = request.result;
                if (!db.objectStoreNames.contains(LOG_STORE)) {
                    db.createObjectStore(LOG_STORE, {keyPath: 'key'});
                }
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async function dbGet(key) {
        const db = await openDb();
        return new Promise((resolve, reject) => {
            const request = db.transaction(LOG_STORE, 'readonly').objectStore(LOG_STORE).get(key);
            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject(request.error);
        });
    }

    async function dbPut(value) {
        const db = await openDb();
        return new Promise((resolve, reject) => {
            const request = db.transaction(LOG_STORE, 'readwrite').objectStore(LOG_STORE).put(value);
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
    }

    async function dbDeleteOldLogCaches() {
        const db = await openDb();
        const base = (apiBase() || 'same-origin') + '|v';
        const current = base + LOG_CACHE_VERSION + '|';
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(LOG_STORE, 'readwrite');
            const store = transaction.objectStore(LOG_STORE);
            const request = store.getAllKeys();
            request.onsuccess = () => {
                for (const key of request.result || []) {
                    if (String(key).startsWith(base) && !String(key).startsWith(current)) {
                        store.delete(key);
                    }
                }
            };
            request.onerror = () => reject(request.error);
            transaction.oncomplete = () => resolve();
            transaction.onerror = () => reject(transaction.error);
        });
    }

    function emptyBucket() {
        const bots = {};
        for (const [name] of BOT_PATTERNS) bots[name] = 0;
        return {
            total: 0,
            bots,
            ips: {},
            botIps: {},
            referrerIps: {},
            searchIps: {},
            userIps: {},
            unknownSourceIps: {}
        };
    }

    function emptyLogCache(file) {
        return {
            key: (apiBase() || 'same-origin') + '|v' + LOG_CACHE_VERSION + '|' + file.id,
            id: file.id,
            name: file.name,
            offset: 0,
            size: 0,
            savedAt: 0,
            tail: '',
            all: emptyBucket(),
            success: emptyBucket(),
            errors: emptyBucket(),
            statusBuckets: {},
            blocked: []
        };
    }

    function identifyBot(ua) {
        for (const [name, label, pattern] of BOT_PATTERNS) {
            if (pattern.test(ua)) return {name, label};
        }
        return null;
    }

    function parseLogLine(line) {
        const match = line.match(
            /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+\S+\s+"([^"]*)"\s+"([^"]*)"/
        );
        if (!match) return null;
        const request = match[3];
        const parts = request.split(/\s+/);
        return {
            ip: match[1],
            time: match[2],
            request,
            path: parts.length >= 2 ? parts[1] : request,
            status: Number(match[4]),
            referrer: match[5],
            ua: match[6]
        };
    }

    function hasReferrer(event) {
        return Boolean(event.referrer && event.referrer !== '-');
    }

    function isSearchReferrer(referrer) {
        if (!referrer || referrer === '-') return false;
        return /(?:baidu|google|bing|sogou|so\.com|360|sm\.cn|yandex|duckduckgo|chatgpt|openai|doubao|toutiao|bytes|perplexity|quark|shenma)/i.test(referrer);
    }

    function isBrowserUserAgent(ua) {
        return /Mozilla|Chrome|Safari|Firefox|Edg|OPR|MicroMessenger|QQBrowser|Quark|UCBrowser|Mobile/i.test(ua || '');
    }

    function addEvent(bucket, event, bot) {
        bucket.total += 1;
        bucket.ips[event.ip] = (bucket.ips[event.ip] || 0) + 1;
        if (hasReferrer(event)) {
            bucket.referrerIps[event.ip] = (bucket.referrerIps[event.ip] || 0) + 1;
        }
        if (bot) {
            bucket.bots[bot.name] = (bucket.bots[bot.name] || 0) + 1;
            bucket.botIps[event.ip] = bot.label;
        }
        if (bot || isSearchReferrer(event.referrer)) {
            bucket.searchIps[event.ip] = (bucket.searchIps[event.ip] || 0) + 1;
        } else if (isBrowserUserAgent(event.ua)) {
            bucket.userIps[event.ip] = (bucket.userIps[event.ip] || 0) + 1;
        } else if (hasReferrer(event)) {
            bucket.unknownSourceIps[event.ip] = (bucket.unknownSourceIps[event.ip] || 0) + 1;
        }
    }

    function processText(cache, text) {
        const combined = (cache.tail || '') + text;
        const lines = combined.split(/\r?\n/);
        cache.tail = lines.pop() || '';
        for (const line of lines) {
            const event = parseLogLine(line);
            if (!event) continue;
            const bot = identifyBot(event.ua);
            const statusKey = String(event.status);
            if (!cache.statusBuckets) cache.statusBuckets = {};
            if (!cache.statusBuckets[statusKey]) cache.statusBuckets[statusKey] = emptyBucket();
            addEvent(cache.all, event, bot);
            addEvent(cache.statusBuckets[statusKey], event, bot);
            if (event.status < 400) addEvent(cache.success, event, bot);
            else {
                if (!cache.errors) cache.errors = emptyBucket();
                addEvent(cache.errors, event, bot);
            }
            if (event.status === 444) {
                cache.blocked.push({
                    ip: event.ip,
                    time: event.time,
                    path: event.path,
                    request: event.request,
                    referrer: event.referrer,
                    ua: event.ua,
                    bot: bot ? bot.label : ''
                });
            }
        }
    }

    async function fetchLogManifest() {
        const response = await fetch(apiUrl('/api/logs/manifest'), {cache: 'no-store'});
        if (!response.ok) throw new Error('日志清单加载失败：HTTP ' + response.status);
        const data = await response.json();
        return data.files || [];
    }

    async function ensureFileCache(file, progress) {
        const key = (apiBase() || 'same-origin') + '|v' + LOG_CACHE_VERSION + '|' + file.id;
        let cache = await dbGet(key);
        if (!cache || cache.id !== file.id || cache.offset > file.size) {
            cache = emptyLogCache(file);
        }
        if (file.gzip && cache.offset !== 0 && cache.offset !== file.size) {
            cache = emptyLogCache(file);
        }
        while (cache.offset < file.size) {
            const url = '/api/logs/chunk?index=' + file.index +
                '&id=' + encodeURIComponent(file.id) + '&offset=' + cache.offset;
            const response = await fetch(apiUrl(url), {cache: 'no-store'});
            if (response.status === 409 || response.status === 416) {
                throw new Error('日志已轮转，请重新加载');
            }
            if (!response.ok) throw new Error('日志读取失败：HTTP ' + response.status);
            const nextOffset = Number(response.headers.get('X-Next-Offset'));
            const buffer = await response.arrayBuffer();
            processText(cache, new TextDecoder('utf-8').decode(buffer));
            if (!Number.isFinite(nextOffset) || nextOffset <= cache.offset) break;
            cache.offset = nextOffset;
            cache.size = file.size;
            if (progress) progress(file, cache.offset, file.size);
            await new Promise(resolve => setTimeout(resolve, 0));
        }
        cache.size = file.size;
        cache.name = file.name;
        cache.savedAt = Date.now();
        await dbPut(cache);
        return cache;
    }

    async function readLogCaches(files) {
        await dbDeleteOldLogCaches();
        const result = [];
        for (const file of files) {
            const key = (apiBase() || 'same-origin') + '|v' + LOG_CACHE_VERSION + '|' + file.id;
            const cache = await dbGet(key);
            if (cache && cache.id === file.id && cache.offset <= file.size) {
                result.push({file, cache});
            }
        }
        return result;
    }

    async function refreshLogCaches(files, progress) {
        await dbDeleteOldLogCaches();
        const result = [];
        for (const file of files) {
            result.push({file, cache: await ensureFileCache(file, progress)});
        }
        return result;
    }

    async function loadLogCaches(progress) {
        const files = await fetchLogManifest();
        return refreshLogCaches(files, progress);
    }

    function mergeInto(result, bucket) {
        if (!bucket) return;
        result.total += bucket.total || 0;
        for (const [name, count] of Object.entries(bucket.bots || {})) {
            result.bots[name] = (result.bots[name] || 0) + count;
        }
        for (const [ip, count] of Object.entries(bucket.ips || {})) {
            result.ips[ip] = (result.ips[ip] || 0) + count;
        }
        Object.assign(result.botIps, bucket.botIps || {});
        for (const [ip, count] of Object.entries(bucket.referrerIps || {})) {
            result.referrerIps[ip] = (result.referrerIps[ip] || 0) + count;
        }
        for (const [ip, count] of Object.entries(bucket.searchIps || {})) {
            result.searchIps[ip] = (result.searchIps[ip] || 0) + count;
        }
        for (const [ip, count] of Object.entries(bucket.userIps || {})) {
            result.userIps[ip] = (result.userIps[ip] || 0) + count;
        }
        for (const [ip, count] of Object.entries(bucket.unknownSourceIps || {})) {
            result.unknownSourceIps[ip] = (result.unknownSourceIps[ip] || 0) + count;
        }
    }

    function mergeBuckets(items, mode) {
        const result = emptyBucket();
        for (const item of items) {
            if (mode === 'all') {
                mergeInto(result, item.cache.all);
            } else if (mode === 'lt400' || mode === 'success') {
                mergeInto(result, item.cache.success);
            } else if (mode === 'gte400') {
                if (item.cache.errors) {
                    mergeInto(result, item.cache.errors);
                } else {
                    for (const [status, bucket] of Object.entries(item.cache.statusBuckets || {})) {
                        if (Number(status) >= 400) mergeInto(result, bucket);
                    }
                }
            } else if (mode === 'not444') {
                for (const [status, bucket] of Object.entries(item.cache.statusBuckets || {})) {
                    if (String(status) !== '444') mergeInto(result, bucket);
                }
            } else if (/^\d{3}$/.test(String(mode))) {
                mergeInto(result, (item.cache.statusBuckets || {})[String(mode)]);
            }
        }
        return result;
    }

    function ipToNum(ip) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4 || parts.some(n => !Number.isInteger(n) || n < 0 || n > 255)) {
            return NaN;
        }
        return ((parts[0] * 0x1000000) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0;
    }

    function numToIp(value) {
        const number = value >>> 0;
        return [
            number >>> 24,
            (number >>> 16) & 255,
            (number >>> 8) & 255,
            number & 255
        ].join('.');
    }

    function maskFor(bits) {
        if (bits === 0) return 0;
        return (0xffffffff << (32 - bits)) >>> 0;
    }

    const IPV6_MAX = (1n << 128n) - 1n;

    function ipv6ToBigInt(ip) {
        let value = String(ip || '').toLowerCase();
        if (!value || value.includes('%') || (value.match(/::/g) || []).length > 1) return null;
        if (value.includes('.')) {
            const lastColon = value.lastIndexOf(':');
            if (lastColon < 0) return null;
            const ipv4 = ipToNum(value.slice(lastColon + 1));
            if (!Number.isFinite(ipv4)) return null;
            value = value.slice(0, lastColon) + ':' +
                ((ipv4 >>> 16) & 0xffff).toString(16) + ':' +
                (ipv4 & 0xffff).toString(16);
        }
        const compressed = value.includes('::');
        const halves = value.split('::');
        const left = halves[0] ? halves[0].split(':') : [];
        const right = halves.length > 1 && halves[1] ? halves[1].split(':') : [];
        if ([...left, ...right].some(part => !/^[0-9a-f]{1,4}$/.test(part))) return null;
        const missing = 8 - left.length - right.length;
        if ((compressed && missing < 1) || (!compressed && missing !== 0)) return null;
        const groups = [...left, ...Array(compressed ? missing : 0).fill('0'), ...right];
        if (groups.length !== 8) return null;
        return groups.reduce((result, part) => (result << 16n) | BigInt('0x' + part), 0n);
    }

    function bigIntToIpv6(value) {
        const groups = [];
        let number = value & IPV6_MAX;
        for (let index = 7; index >= 0; index -= 1) {
            groups[index] = Number(number & 0xffffn).toString(16);
            number >>= 16n;
        }
        let bestStart = -1;
        let bestLength = 0;
        for (let index = 0; index < groups.length;) {
            if (groups[index] !== '0') {
                index += 1;
                continue;
            }
            let end = index;
            while (end < groups.length && groups[end] === '0') end += 1;
            if (end - index > bestLength && end - index >= 2) {
                bestStart = index;
                bestLength = end - index;
            }
            index = end;
        }
        if (bestStart < 0) return groups.join(':');
        const left = groups.slice(0, bestStart).join(':');
        const right = groups.slice(bestStart + bestLength).join(':');
        return left + '::' + right;
    }

    function maskForV6(bits) {
        if (bits === 0) return 0n;
        return (IPV6_MAX << BigInt(128 - bits)) & IPV6_MAX;
    }

    function parseConfig(content) {
        const rules = [];
        const invalid = [];
        content.split(/\r?\n/).forEach((original, index) => {
            const body = original.split('#', 1)[0].trim();
            if (!body) return;
            const parts = body.split(/\s+/);
            const key = (parts[0] || '').replace(/;$/, '');
            const valueText = (parts[1] || '').replace(/;$/, '');
            if ((!/^\d/.test(key) && !key.includes(':')) || !['0', '1'].includes(valueText)) return;
            const separator = key.lastIndexOf('/');
            const address = separator >= 0 ? key.slice(0, separator) : key;
            const version = address.includes(':') ? 6 : 4;
            const bits = separator >= 0 ? Number(key.slice(separator + 1)) : (version === 6 ? 128 : 32);
            const ipNumber = version === 6 ? ipv6ToBigInt(address) : ipToNum(address);
            const maxBits = version === 6 ? 128 : 32;
            if (
                (version === 6 ? ipNumber === null : !Number.isFinite(ipNumber)) ||
                !Number.isInteger(bits) || bits < 0 || bits > maxBits
            ) {
                invalid.push({line: index + 1, rule: key});
                return;
            }
            const base = version === 6
                ? ipNumber & maskForV6(bits)
                : (ipNumber & maskFor(bits)) >>> 0;
            const canonicalAddress = version === 6 ? bigIntToIpv6(base) : numToIp(base);
            rules.push({
                line: index + 1,
                original,
                rule: key,
                value: Number(valueText),
                version,
                bits,
                base,
                canonical: bits === maxBits ? canonicalAddress : canonicalAddress + '/' + bits,
                ipCount: version === 6 ? 1n << BigInt(128 - bits) : Math.pow(2, 32 - bits)
            });
        });
        return {rules, invalid};
    }

    function buildMatcher(content) {
        const parsed = parseConfig(content);
        const byPrefix = Array.from({length: 33}, () => new Map());
        const byPrefixV6 = Array.from({length: 129}, () => new Map());
        for (const rule of parsed.rules) {
            const target = rule.version === 6 ? byPrefixV6 : byPrefix;
            target[rule.bits].set(rule.base, rule.value);
        }
        return {
            parsed,
            match(ip) {
                if (String(ip).includes(':')) {
                    const number = ipv6ToBigInt(ip);
                    if (number === null) return false;
                    for (let bits = 128; bits >= 0; bits -= 1) {
                        const value = byPrefixV6[bits].get(number & maskForV6(bits));
                        if (value !== undefined) return value === 1;
                    }
                    return false;
                }
                const number = ipToNum(ip);
                if (!Number.isFinite(number)) return false;
                for (let bits = 32; bits >= 0; bits -= 1) {
                    const value = byPrefix[bits].get((number & maskFor(bits)) >>> 0);
                    if (value !== undefined) return value === 1;
                }
                return false;
            }
        };
    }

    function escapeHtml(value) {
        return String(value).replace(/[&<>"']/g, char => ({
            '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[char]);
    }

    window.NSL = {
        BOT_PATTERNS,
        load,
        save,
        apiBase,
        apiUrl,
        configureApiInput,
        fetchConfig,
        saveConfig,
        fetchLogManifest,
        readLogCaches,
        refreshLogCaches,
        loadLogCaches,
        mergeBuckets,
        parseLogLine,
        identifyBot,
        parseConfig,
        buildMatcher,
        ipToNum,
        numToIp,
        maskFor,
        ipv6ToBigInt,
        bigIntToIpv6,
        maskForV6,
        escapeHtml
    };
    loadDlcNavigation();
})();
