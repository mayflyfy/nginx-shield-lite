(function () {
    'use strict';

    const PAGE_SIZE = 150;
    const state = {
        logItems: [],
        groups: [],
        page: 1,
        prefixes: [],
        black: null,
        trusted: null,
        stalePrompted: false
    };
    const $ = id => document.getElementById(id);
    const esc = NSL.escapeHtml;
    NSL.configureApiInput($('api_base'));

    const FILTER_IDS = ['query', 'min_count', 'reason_filter', 'sort'];
    for (const id of FILTER_IDS) {
        const saved = NSL.load('ui_444_' + id, null);
        if (saved !== null) $(id).value = saved;
    }

    function formatNumber(value) {
        return Number(value || 0).toLocaleString('zh-CN');
    }

    function prefixKey() {
        return '444_prefixes_' + encodeURIComponent(NSL.apiBase() || 'same-origin');
    }

    function loadPrefixes() {
        try {
            state.prefixes = JSON.parse(NSL.load(prefixKey(), '[]'));
            if (!Array.isArray(state.prefixes)) state.prefixes = [];
        } catch (_) {
            state.prefixes = [];
        }
    }

    function savePrefixes() {
        NSL.save(prefixKey(), JSON.stringify(state.prefixes));
    }

    function normalizePrefix(value) {
        const prefix = value.trim();
        if (!prefix || !/^\d{1,3}(?:\.\d{0,3}){0,3}$/.test(prefix)) return null;
        const parts = prefix.split('.').filter(Boolean);
        if (parts.some(part => Number(part) > 255)) return null;
        return prefix;
    }

    function renderPrefixes() {
        $('prefix_list').innerHTML = state.prefixes.map((prefix, index) =>
            '<span class="prefix-chip mono">' + esc(prefix) +
            '<button data-index="' + index + '" title="删除">×</button></span>'
        ).join('') || '<span class="muted">没有排除前缀</span>';
        document.querySelectorAll('.prefix-chip button').forEach(button => {
            button.onclick = () => {
                state.prefixes.splice(Number(button.dataset.index), 1);
                savePrefixes();
                renderPrefixes();
                state.page = 1;
                render();
            };
        });
    }

    function addPrefix(value) {
        const prefix = normalizePrefix(value);
        if (!prefix) {
            alert('请输入合法 IP 前缀，例如 66.249. 或 192.168.1.');
            return;
        }
        if (!state.prefixes.includes(prefix)) state.prefixes.push(prefix);
        savePrefixes();
        renderPrefixes();
        $('prefix_input').value = '';
        state.page = 1;
        render();
    }

    function increment(counter, key) {
        if (!key || key === '-') return;
        counter[key] = (counter[key] || 0) + 1;
    }

    function topValue(counter) {
        const entries = Object.entries(counter);
        if (!entries.length) return '';
        entries.sort((a, b) => b[1] - a[1]);
        return entries[0][0];
    }

    function normalizeReferrer(referrer) {
        const value = String(referrer || '').trim();
        if (!value || value === '-' || value.length < 8) return '';
        return value;
    }

    function isSearchReferrer(referrer) {
        const value = normalizeReferrer(referrer);
        if (!value) return false;
        return /(?:baidu|google|bing|sogou|so\.com|360|sm\.cn|yandex|duckduckgo|chatgpt|openai|doubao|toutiao|bytes|perplexity|quark|shenma)/i.test(value);
    }

    function isBrowserUserAgent(ua) {
        return /Mozilla|Chrome|Safari|Firefox|Edg|OPR|MicroMessenger|QQBrowser|Quark|UCBrowser|Mobile/i.test(ua || '');
    }

    function sourceTypeLabel(group) {
        const referrer = normalizeReferrer(group.referrer);
        if (group.bot || isSearchReferrer(referrer)) return '搜索/AI来源';
        if (referrer && isBrowserUserAgent(group.ua)) return '用户来源';
        return '其他/无来源';
    }

    function buildGroups() {
        const map = new Map();
        for (const item of state.logItems) {
            for (const record of item.cache.blocked || []) {
                let group = map.get(record.ip);
                if (!group) {
                    group = {
                        ip: record.ip,
                        count: 0,
                        first: record.time,
                        last: record.time,
                        paths: {},
                        uas: {},
                        refs: {},
                        bots: {}
                    };
                    map.set(record.ip, group);
                }
                group.count += 1;
                if (record.time < group.first) group.first = record.time;
                if (record.time > group.last) group.last = record.time;
                increment(group.paths, record.path);
                increment(group.uas, record.ua);
                increment(group.refs, record.referrer);
                increment(group.bots, record.bot);
            }
        }
        state.groups = Array.from(map.values()).map(group => ({
            ...group,
            path: topValue(group.paths),
            ua: topValue(group.uas),
            referrer: topValue(group.refs),
            bot: topValue(group.bots)
        }));
    }

    function ipSortKey(ip) {
        return ip.split('.').map(part => part.padStart(3, '0')).join('');
    }

    function classify(group) {
        const black = state.black && state.black.matcher.match(group.ip);
        const trusted = state.trusted && state.trusted.matcher.match(group.ip);
        return {black, trusted, blocked: black && !trusted, bot: Boolean(group.bot)};
    }

    function filteredGroups() {
        const query = $('query').value.trim().toLowerCase();
        const minimum = Number($('min_count').value) || 1;
        const reason = $('reason_filter').value;
        const rows = state.groups.filter(group => {
            if (group.count < minimum) return false;
            if (state.prefixes.some(prefix => group.ip.startsWith(prefix))) return false;
            const type = classify(group);
            if (reason === 'black' && !type.blocked) return false;
            if (reason === 'other' && type.blocked) return false;
            if (reason === 'bot' && !type.bot) return false;
            if (query && ![
                group.ip, group.path, group.ua, group.referrer, group.bot
            ].some(value => String(value || '').toLowerCase().includes(query))) return false;
            return true;
        });
        const sort = $('sort').value;
        if (sort === 'ip') rows.sort((a, b) => ipSortKey(a.ip).localeCompare(ipSortKey(b.ip)));
        else if (sort === 'recent') rows.sort((a, b) => b.last.localeCompare(a.last));
        else rows.sort((a, b) => b.count - a.count);
        return rows;
    }

    function render() {
        const rows = filteredGroups();
        const excluded = state.groups.filter(group =>
            state.prefixes.some(prefix => group.ip.startsWith(prefix))
        ).length;
        const totalEvents = state.groups.reduce((sum, group) => sum + group.count, 0);
        const visibleEvents = rows.reduce((sum, group) => sum + group.count, 0);
        const pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
        state.page = Math.min(state.page, pages);
        const start = (state.page - 1) * PAGE_SIZE;
        $('summary').textContent =
            formatNumber(visibleEvents) + ' / ' + formatNumber(totalEvents) + ' 次，' +
            rows.length + ' / ' + state.groups.length + ' IP；前缀排除 ' + excluded + ' IP';
        $('rows').innerHTML = rows.slice(start, start + PAGE_SIZE).map((group, index) => {
            const type = classify(group);
            const sourceType = sourceTypeLabel(group);
            const rawReferrer = normalizeReferrer(group.referrer) || '-';
            const labels = [
                type.blocked ? '<span class="tag">当前IP封禁</span>' :
                    (type.black && type.trusted ? '<span class="tag">白名单已覆盖黑名单</span>' : '<span class="tag">非IP规则</span>'),
                type.trusted && !type.black ? '<span class="tag">已在白名单</span>' : '',
                group.bot ? '<span class="tag">' + esc(group.bot) + '</span>' : ''
            ].join('');
            const prefix = group.ip.split('.').slice(0, 3).join('.') + '.';
            return '<tr><td>' + (start + index + 1) + '</td>' +
                '<td class="mono">' + esc(group.ip) + '<br>' + labels + '</td>' +
                '<td>' + formatNumber(group.count) + '</td>' +
                '<td class="nowrap"><small>' + esc(group.first) + '<br>' + esc(group.last) + '</small></td>' +
                '<td style="max-width:520px;white-space:normal"><b>路径：</b><span class="mono">' + esc(group.path || '-') + '</span><br>' +
                '<b>UA：</b>' + esc(group.ua || '-') + '<br><b>来源类型：</b>' + esc(sourceType) +
                '<br><b>原始来源：</b>' + esc(rawReferrer) + '</td>' +
                '<td class="nowrap"><button class="hide-prefix" data-prefix="' + esc(prefix) + '">不看 ' + esc(prefix) + '*</button><br>' +
                '<button class="trust-ip primary" data-ip="' + esc(group.ip) + '" ' + (type.trusted ? 'disabled' : '') + '>加入白名单</button></td></tr>';
        }).join('') || '<tr><td colspan="6" class="empty">没有符合筛选条件的 444 记录</td></tr>';
        document.querySelectorAll('.hide-prefix').forEach(button => {
            button.onclick = () => addPrefix(button.dataset.prefix);
        });
        document.querySelectorAll('.trust-ip').forEach(button => {
            button.onclick = () => trustIp(button.dataset.ip);
        });
        $('pager').innerHTML =
            '<span>第 ' + state.page + '/' + pages + ' 页</span>' +
            '<button id="prev" ' + (state.page <= 1 ? 'disabled' : '') + '>上一页</button>' +
            '<button id="next" ' + (state.page >= pages ? 'disabled' : '') + '>下一页</button>';
        $('prev').onclick = () => {state.page -= 1; render();};
        $('next').onclick = () => {state.page += 1; render();};
    }

    async function trustIp(ip) {
        const number = NSL.ipToNum(ip);
        const rule = Number.isFinite(number)
            ? NSL.numToIp((number & NSL.maskFor(24)) >>> 0) + '/24'
            : ip;
        if (!confirm('确认把 ' + rule + ' 加入共享 trusted_ip.conf？所有应用都会放行该网段。')) return;
        try {
            const latest = await NSL.fetchConfig('trusted', true);
            const matcher = NSL.buildMatcher(latest.content);
            if (matcher.match(ip)) {
                state.trusted = {content: latest.content, matcher};
                render();
                return;
            }
            const content = latest.content.replace(/\s*$/, '') + '\n' + rule + ' 1;\n';
            await NSL.saveConfig('trusted', content);
            state.trusted = {content, matcher: NSL.buildMatcher(content)};
            render();
        } catch (error) {
            alert(error.message);
        }
    }

    async function load(forceRefresh = false) {
        $('log_progress').style.display = 'block';
        try {
            const [black, trusted] = await Promise.all([
                NSL.fetchConfig('black'),
                NSL.fetchConfig('trusted')
            ]);
            state.black = {content: black.content, matcher: NSL.buildMatcher(black.content)};
            state.trusted = {content: trusted.content, matcher: NSL.buildMatcher(trusted.content)};
            const manifest = await NSL.fetchLogManifest();
            const current = manifest.find(file => file.name === 'access.log') || manifest[0];
            const files = current ? [current] : [];
            const cached = forceRefresh ? [] : await NSL.readLogCaches(files);
            if (!forceRefresh && cached.length === files.length && cached.length) {
                state.logItems = cached;
                const age = Date.now() - Number(cached[0].cache.savedAt || 0);
                if (age <= 30 * 60 * 1000 || state.stalePrompted ||
                    !confirm('444 日志缓存已超过 30 分钟，是否读取 access.log 新增内容？')) {
                    state.stalePrompted = age > 30 * 60 * 1000;
                    buildGroups();
                    render();
                    $('log_progress_text').textContent = '已读取 access.log 浏览器缓存';
                    $('log_progress_bar').style.width = '100%';
                    setTimeout(() => {$('log_progress').style.display = 'none';}, 800);
                    return;
                }
                state.stalePrompted = true;
            }
            state.logItems = await NSL.refreshLogCaches(files, (file, offset, size) => {
                $('log_progress_text').textContent =
                    '浏览器解析 ' + file.name + '：' + formatNumber(offset) + ' / ' + formatNumber(size) + ' 字节';
                $('log_progress_bar').style.width = (size ? offset / size * 100 : 100) + '%';
            });
            buildGroups();
            render();
            $('log_progress_text').textContent = '444 浏览器缓存已更新';
            $('log_progress_bar').style.width = '100%';
            setTimeout(() => {$('log_progress').style.display = 'none';}, 800);
        } catch (error) {
            $('log_progress_text').textContent = error.message;
            $('log_progress_text').className = 'error';
        }
    }

    loadPrefixes();
    renderPrefixes();
    $('prefix_add').onclick = () => addPrefix($('prefix_input').value);
    $('prefix_input').onkeydown = event => {if (event.key === 'Enter') addPrefix($('prefix_input').value);};
    $('prefix_clear').onclick = () => {
        if (!state.prefixes.length || confirm('清空全部 IP 前缀过滤规则？')) {
            state.prefixes = [];
            savePrefixes();
            renderPrefixes();
            state.page = 1;
            render();
        }
    };
    for (const id of FILTER_IDS) {
        $(id).addEventListener(id === 'query' || id === 'min_count' ? 'input' : 'change', () => {
            NSL.save('ui_444_' + id, $(id).value);
            state.page = 1;
            render();
        });
    }
    $('refresh_logs').onclick = () => load(true);
    load(false);
})();
