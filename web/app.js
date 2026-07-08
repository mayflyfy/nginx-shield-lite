(function () {
    'use strict';

    const state = {
        activeList: 'black',
        configs: {black: null, trusted: null},
        analysis: null,
        rulePage: 1,
        ipPage: 1,
        logFiles: [],
        logItems: [],
        allBucket: null,
        bucket: null,
        stalePrompted: new Set()
    };

    const $ = id => document.getElementById(id);
    const esc = NSL.escapeHtml;

    NSL.configureApiInput($('api_base'));

    const CONTROL_PREFERENCES = {
        status_scope: 'value',
        ip_min: 'value',
        ip_scope: 'value',
        source_scope: 'value',
        hide_bots: 'checked',
        ip_sort: 'value',
        ip_page_size: 'value',
        rule_page_size: 'value',
        rule_search: 'value'
    };

    function restorePreferences() {
        for (const [id, property] of Object.entries(CONTROL_PREFERENCES)) {
            const element = $(id);
            const saved = NSL.load('ui_' + id, null);
            if (saved === null) continue;
            if (property === 'checked') element.checked = saved === '1';
            else if ([...element.options || []].length) {
                if ([...element.options].some(option => option.value === saved)) element.value = saved;
            } else {
                element.value = saved;
            }
        }
        for (const [buttonId, scrollId] of [
            ['ip_expand', 'ip_scroll'],
            ['rule_expand', 'rule_scroll']
        ]) {
            const expanded = NSL.load('ui_' + scrollId + '_expanded', '0') === '1';
            $(scrollId).classList.toggle('expanded', expanded);
            $(buttonId).textContent = expanded ? '收起列表' : '展开列表';
        }
    }

    function rememberControl(id) {
        const property = CONTROL_PREFERENCES[id];
        NSL.save('ui_' + id, property === 'checked' ? ($(id).checked ? '1' : '0') : $(id).value);
    }

    restorePreferences();

    function formatNumber(value) {
        if (typeof value === 'bigint') return value.toLocaleString('zh-CN');
        return Number(value || 0).toLocaleString('zh-CN');
    }

    function downloadText(filename, content, mimeType) {
        const blob = new Blob([content], {type: mimeType + ';charset=utf-8'});
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 0);
    }

    function csvCell(value) {
        let text = String(value == null ? '' : value);
        if (/^[=+\-@]/.test(text)) text = "'" + text;
        return '"' + text.replace(/"/g, '""') + '"';
    }

    function ipSortKey(ip) {
        return ip.split('.').map(part => part.padStart(3, '0')).join('');
    }

    function listPath(name) {
        return name === 'black'
            ? '/etc/nginx/conf.d/black_ip.conf'
            : '/etc/nginx/conf.d/trusted_ip.conf';
    }

    function analyzeInBrowser(content) {
        const parsed = NSL.parseConfig(content);
        const blockRules = parsed.rules.filter(rule => rule.value === 1);
        const allowRules = parsed.rules.filter(rule => rule.value === 0);
        const duplicateLines = new Map();
        const seen = new Map();
        for (const rule of parsed.rules) {
            const key = rule.value + ':' + rule.canonical;
            if (seen.has(key)) duplicateLines.set(rule.line, '与第' + seen.get(key) + '行重复');
            else seen.set(key, rule.line);
        }

        const prefixMaps = {
            4: Array.from({length: 33}, () => new Set()),
            6: Array.from({length: 129}, () => new Set())
        };
        for (const rule of blockRules) prefixMaps[rule.version][rule.bits].add(rule.base);
        const containedLines = new Map();
        if (!allowRules.length) {
            for (const rule of blockRules) {
                if (duplicateLines.has(rule.line)) continue;
                for (let bits = rule.bits - 1; bits >= 0; bits -= 1) {
                    const base = rule.version === 6
                        ? rule.base & NSL.maskForV6(bits)
                        : (rule.base & NSL.maskFor(bits)) >>> 0;
                    if (prefixMaps[rule.version][bits].has(base)) {
                        containedLines.set(rule.line, '已被 /' + bits + ' 大段包含');
                        break;
                    }
                }
            }
        }

        const ipv4BlockRules = blockRules.filter(rule => rule.version === 4);
        const intervals = ipv4BlockRules.map(rule => ({
            start: rule.base,
            end: rule.base + rule.ipCount - 1
        })).sort((a, b) => a.start - b.start || a.end - b.end);
        let unique = 0;
        let current = null;
        for (const interval of intervals) {
            if (!current || interval.start > current.end + 1) {
                if (current) unique += current.end - current.start + 1;
                current = {...interval};
            } else {
                current.end = Math.max(current.end, interval.end);
            }
        }
        if (current) unique += current.end - current.start + 1;
        if (allowRules.length) {
            // Exact effective counting with nested allow/reblock remains available
            // in the Python compatibility API; generated deployment lists contain
            // block-only rules, so the fast browser union is exact in normal use.
            unique = Math.max(
                0,
                unique - allowRules
                    .filter(rule => rule.version === 4)
                    .reduce((sum, rule) => sum + rule.ipCount, 0)
            );
        }

        const rows = parsed.rules.map(rule => ({
            ...rule,
            issue: duplicateLines.get(rule.line) || containedLines.get(rule.line) || ''
        }));
        return {
            rows,
            invalid: parsed.invalid,
            duplicates: duplicateLines.size,
            contained: containedLines.size,
            blockCount: blockRules.length,
            allowCount: allowRules.length,
            ipv6Count: parsed.rules.filter(rule => rule.version === 6).length,
            unique
        };
    }

    function updateDirty() {
        const config = state.configs[state.activeList];
        const dirty = config && $('list_content').value !== config.savedContent;
        $('dirty_state').textContent = dirty ? '有未保存修改' : '已同步';
        $('dirty_state').className = 'status ' + (dirty ? 'warn' : 'ok');
    }

    let analyzeTimer = null;
    function scheduleAnalysis() {
        clearTimeout(analyzeTimer);
        analyzeTimer = setTimeout(() => {
            const content = $('list_content').value;
            const config = state.configs[state.activeList];
            config.content = content;
            config.matcher = NSL.buildMatcher(content);
            state.analysis = analyzeInBrowser(content);
            state.rulePage = 1;
            renderList();
            renderIps();
        }, 80);
    }

    function renderList() {
        const analysis = state.analysis;
        if (!analysis) return;
        $('list_summary').innerHTML =
            '<div class="card"><b>' + formatNumber(analysis.blockCount) + '</b><span>规则（IPv6 ' + formatNumber(analysis.ipv6Count) + '）</span></div>' +
            '<div class="card"><b>' + formatNumber(analysis.unique) + '</b><span>覆盖 IPv4</span></div>' +
            '<div class="card"><b>' + formatNumber(analysis.invalid.length + analysis.duplicates + analysis.contained) + '</b><span>问题</span></div>';
        const issues = [];
        if (analysis.invalid.length) issues.push(analysis.invalid.length + ' 条格式错误');
        if (analysis.duplicates) issues.push(analysis.duplicates + ' 条重复');
        if (analysis.contained) issues.push(analysis.contained + ' 条被大段包含');
        if (analysis.allowCount) issues.push(analysis.allowCount + ' 条 allow；覆盖数为快速估算');
        $('list_issues').style.display = issues.length ? 'block' : 'none';
        $('list_issues').textContent = issues.join('，');

        const query = $('rule_search').value.trim();
        const rows = analysis.rows.filter(row => !query || row.canonical.includes(query));
        const pageSize = Number($('rule_page_size').value) || 100;
        const pages = Math.max(1, Math.ceil(rows.length / pageSize));
        state.rulePage = Math.min(state.rulePage, pages);
        const start = (state.rulePage - 1) * pageSize;
        $('rule_rows').innerHTML = rows.slice(start, start + pageSize).map(row =>
            '<tr class="' + (row.issue ? 'warn' : '') + '">' +
            '<td><input class="mono rule-value" data-line="' + row.line + '" data-value="' + row.value + '" value="' + esc(row.canonical) + '" style="width:100%">' +
            (row.issue ? '<small class="warn"> ' + esc(row.issue) + '</small>' : '') + '</td>' +
            '<td>' + formatNumber(row.ipCount) + '</td>' +
            '<td><button class="danger delete-rule btn-xs" data-line="' + row.line + '">删除</button></td></tr>'
        ).join('') || '<tr><td colspan="3" class="empty">没有匹配规则</td></tr>';
        $('rule_pager').innerHTML =
            '<span>' + formatNumber(rows.length) + ' 条，第 ' + state.rulePage + '/' + pages + ' 页</span>' +
            '<button id="rule_prev" ' + (state.rulePage <= 1 ? 'disabled' : '') + '>上一页</button>' +
            '<button id="rule_next" ' + (state.rulePage >= pages ? 'disabled' : '') + '>下一页</button>';
        $('rule_prev').onclick = () => {state.rulePage -= 1; renderList();};
        $('rule_next').onclick = () => {state.rulePage += 1; renderList();};
        document.querySelectorAll('.delete-rule').forEach(button => {
            button.onclick = () => deleteRule(Number(button.dataset.line));
        });
        document.querySelectorAll('.rule-value').forEach(input => {
            input.onchange = () => updateRule(Number(input.dataset.line), input.value, Number(input.dataset.value));
        });
    }

    function setListContent(content) {
        $('list_content').value = content;
        state.configs[state.activeList].content = content;
        updateDirty();
        scheduleAnalysis();
    }

    function updateRule(line, value, ruleValue) {
        const lines = $('list_content').value.split(/\r?\n/);
        const parsed = NSL.parseConfig(value.trim() + ' ' + ruleValue + ';');
        if (!parsed.rules.length || parsed.invalid.length) {
            $('list_msg').textContent = 'IP 或 CIDR 格式错误';
            $('list_msg').className = 'status error';
            return;
        }
        const rule = parsed.rules[0];
        const canonical = rule.version === 4 && rule.bits > 24
            ? NSL.numToIp((rule.base & NSL.maskFor(24)) >>> 0) + '/24'
            : rule.canonical;
        lines[line - 1] = canonical + ' ' + ruleValue + ';';
        setListContent(lines.join('\n'));
    }

    function deleteRule(line) {
        const lines = $('list_content').value.split(/\r?\n/);
        lines.splice(line - 1, 1);
        setListContent(lines.join('\n'));
    }

    async function loadList(name, force = false) {
        state.activeList = name;
        NSL.save('ui_active_list', name);
        document.querySelectorAll('.tab[data-list]').forEach(button => {
            button.classList.toggle('active', button.dataset.list === name);
        });
        $('list_path').textContent = listPath(name);
        $('list_msg').textContent = '加载中…';
        try {
            const result = await NSL.fetchConfig(name, force);
            state.configs[name] = {
                content: result.content,
                savedContent: result.content,
                etag: result.etag,
                matcher: NSL.buildMatcher(result.content)
            };
            $('list_content').value = result.content;
            state.analysis = analyzeInBrowser(result.content);
            state.rulePage = 1;
            $('list_msg').textContent = result.cached ? '已从浏览器缓存加载，服务器版本未变化' : '';
            updateDirty();
            renderList();
            renderIps();
        } catch (error) {
            $('list_msg').textContent = error.message;
            $('list_msg').className = 'status error';
        }
    }

    async function ensureLists() {
        const preferred = NSL.load('ui_active_list', 'black') === 'trusted' ? 'trusted' : 'black';
        await loadList('black');
        try {
            const trusted = await NSL.fetchConfig('trusted');
            state.configs.trusted = {
                content: trusted.content,
                savedContent: trusted.content,
                etag: trusted.etag,
                matcher: NSL.buildMatcher(trusted.content)
            };
        } catch (_) {}
        if (preferred === 'trusted') await loadList('trusted');
    }

    function addRule() {
        const input = $('new_rule');
        const value = input.value.trim();
        if (!value) return;
        const check = NSL.parseConfig(value + ' 1;');
        if (!check.rules.length || check.invalid.length) {
            $('list_msg').textContent = 'IP 或 CIDR 格式错误';
            $('list_msg').className = 'status error';
            return;
        }
        const parsedRule = check.rules[0];
        const canonical = parsedRule.version === 4 && parsedRule.bits > 24
            ? NSL.numToIp((parsedRule.base & NSL.maskFor(24)) >>> 0) + '/24'
            : parsedRule.canonical;
        const content = $('list_content').value.replace(/\s*$/, '');
        setListContent((content ? content + '\n' : '') + canonical + ' 1;\n');
        input.value = '';
        $('list_msg').textContent = canonical !== parsedRule.canonical
            ? 'IPv4 已扩大为 ' + canonical + '，请保存'
            : '已添加，请保存';
        $('list_msg').className = 'status ok';
    }

    function normalizeIpv4PolicyContent(content) {
        const seen = new Set();
        return content.split(/\r?\n/).map(original => {
            const parsed = NSL.parseConfig(original);
            if (parsed.rules.length !== 1 || parsed.invalid.length) return original;
            const rule = parsed.rules[0];
            const canonical = rule.version === 4 && rule.bits > 24
                ? NSL.numToIp((rule.base & NSL.maskFor(24)) >>> 0) + '/24'
                : rule.canonical;
            const key = rule.value + ':' + canonical;
            if (seen.has(key)) return '# 已合并重复规则：' + original.trim();
            seen.add(key);
            const indentation = (original.match(/^\s*/) || [''])[0];
            const commentAt = original.indexOf('#');
            const comment = commentAt >= 0 ? ' ' + original.slice(commentAt).trim() : '';
            return indentation + canonical + ' ' + rule.value + ';' + comment;
        }).join('\n');
    }

    async function saveList() {
        const original = $('list_content').value;
        const content = normalizeIpv4PolicyContent(original);
        if (content !== original) {
            $('list_content').value = content;
            state.analysis = analyzeInBrowser(content);
            renderList();
        }
        $('list_msg').textContent = '保存中…';
        try {
            const result = await NSL.saveConfig(state.activeList, content);
            const config = state.configs[state.activeList];
            config.content = content;
            config.savedContent = content;
            config.etag = result.etag;
            config.matcher = NSL.buildMatcher(content);
            $('list_msg').textContent = '保存成功';
            $('list_msg').className = 'status ok';
            updateDirty();
            renderIps();
        } catch (error) {
            $('list_msg').textContent = error.message;
            $('list_msg').className = 'status error';
        }
    }

    function renderBotStats(bucket) {
        const entries = Object.entries(bucket.bots)
            .filter(([, count]) => count)
            .sort((a, b) => b[1] - a[1]);
        const matched = entries.reduce((sum, entry) => sum + entry[1], 0);
        $('bot_stats').innerHTML =
            '<div class="card"><b>' + formatNumber(bucket.total) + '</b><span>日志请求</span></div>' +
            '<div class="card"><b>' + formatNumber(Object.keys(bucket.ips).length) + '</b><span>唯一 IP</span></div>' +
            '<div class="card"><b>' + formatNumber(matched) + '</b><span>识别爬虫</span></div>' +
            entries.slice(0, 9).map(entry =>
                '<div class="card"><b>' + formatNumber(entry[1]) + '</b><span>' + esc(entry[0]) + '</span></div>'
            ).join('');
    }

    function currentLogItems() {
        return state.logItems;
    }

    function selectedLogFiles() {
        const selected = $('log_file').value;
        if (selected === 'all') return state.logFiles;
        return state.logFiles.filter(file => String(file.index) === selected);
    }

    function renderLogFileOptions() {
        const saved = NSL.load('ui_log_file', null);
        $('log_file').innerHTML = '<option value="all">全部日志</option>' +
            state.logFiles.map(file =>
                '<option value="' + file.index + '">' +
                esc(file.name) + '</option>'
            ).join('');
        const currentFile = state.logFiles.find(file => file.name === 'access.log') || state.logFiles[0];
        const fallback = currentFile ? String(currentFile.index) : 'all';
        $('log_file').value = saved !== null &&
            [...$('log_file').options].some(option => option.value === saved)
            ? saved
            : fallback;
        NSL.save('ui_log_file', $('log_file').value);
    }

    function rebuildBucket() {
        state.allBucket = NSL.mergeBuckets(currentLogItems(), 'all');
        state.bucket = NSL.mergeBuckets(
            currentLogItems(),
            $('status_scope').value
        );
        state.ipPage = 1;
        renderBotStats(state.bucket);
        renderIps();
    }

    function addBlock(ip, bits) {
        if (!state.configs.black) return;
        if (String(ip).includes(':')) {
            if (bits !== 128) return;
            if (state.activeList !== 'black') loadList('black').then(() => appendBlock(ip));
            else appendBlock(ip);
            return;
        }
        const number = NSL.ipToNum(ip);
        const base = (number & NSL.maskFor(bits)) >>> 0;
        const rule = bits === 32 ? NSL.numToIp(base) : NSL.numToIp(base) + '/' + bits;
        if (bits <= 8 && !confirm('将加入大范围规则 ' + rule + '，确认继续？')) return;
        if (state.activeList !== 'black') loadList('black').then(() => appendBlock(rule));
        else appendBlock(rule);
    }

    function appendBlock(rule) {
        if (state.configs.black.matcher.match(rule.split('/')[0])) {
            alert(rule + ' 已被当前黑名单覆盖');
            return;
        }
        const content = $('list_content').value.replace(/\s*$/, '');
        setListContent((content ? content + '\n' : '') + rule + ' 1;\n');
        $('list_msg').textContent = '已添加 ' + rule + '，请保存';
    }

    function ipPolicyStatus(ip) {
        const black = state.configs.black && state.configs.black.matcher;
        const trusted = state.configs.trusted && state.configs.trusted.matcher;
        const blacklisted = Boolean(black && black.match(ip));
        const allowlisted = Boolean(trusted && trusted.match(ip));
        return {
            blacklisted,
            allowlisted,
            blocked: blacklisted && !allowlisted
        };
    }

    function filteredIpRows() {
        if (!state.bucket) return [];
        const min = Number($('ip_min').value) || 0;
        const hideBots = $('hide_bots').checked;
        const scope = $('ip_scope').value;
        const sourceScope = $('source_scope').value;
        let rows = Object.entries(state.bucket.ips).filter(([ip, count]) => {
            const status = ipPolicyStatus(ip);
            const bot = state.bucket.botIps[ip];
            const hasSearchSource = Boolean(bot || state.bucket.searchIps[ip] > 0);
            const hasUserSource = Boolean(state.bucket.userIps[ip] > 0);
            const hasOtherSource = !hasSearchSource && !hasUserSource;
            if (count < min) return false;
            if (hideBots && bot && sourceScope !== 'search') return false;
            if (scope === 'blacklisted' && !status.blacklisted) return false;
            if (scope === 'allowlisted' && !status.allowlisted) return false;
            if (sourceScope === 'search' && !hasSearchSource) return false;
            if (sourceScope === 'user' && (!hasUserSource || hasSearchSource)) return false;
            if ((sourceScope === 'other' || sourceScope === 'unknown' || sourceScope === 'none') && !hasOtherSource) return false;
            return true;
        });
        if ($('ip_sort').value === 'ip') rows.sort((a, b) => ipSortKey(a[0]).localeCompare(ipSortKey(b[0])));
        else rows.sort((a, b) => b[1] - a[1]);
        return rows;
    }

    function exportIps() {
        const lines = [
            ['IP', '访问次数', '命中黑名单', '命中白名单', '有效封禁', '搜索或AI识别', '有效来源请求数'].map(csvCell).join(',')
        ];
        for (const [ip, count] of filteredIpRows()) {
            const status = ipPolicyStatus(ip);
            lines.push([
                ip,
                count,
                status.blacklisted ? '是' : '否',
                status.allowlisted ? '是' : '否',
                status.blocked ? '是' : '否',
                state.bucket.botIps[ip] || '',
                state.bucket.referrerIps[ip] || 0
            ].map(csvCell).join(','));
        }
        const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
        downloadText(
            'nginx-shield-ip-' + stamp + '.csv',
            '\ufeff' + lines.join('\r\n') + '\r\n',
            'text/csv'
        );
    }

    function exportList() {
        const name = state.activeList === 'black' ? 'black_ip.conf' : 'trusted_ip.conf';
        downloadText(name, $('list_content').value, 'text/plain');
        $('list_msg').textContent = '已在浏览器导出 ' + name;
        $('list_msg').className = 'status ok';
    }

    function toggleExpanded(buttonId, scrollId) {
        const expanded = $(scrollId).classList.toggle('expanded');
        $(buttonId).textContent = expanded ? '收起列表' : '展开列表';
        NSL.save('ui_' + scrollId + '_expanded', expanded ? '1' : '0');
    }

    function renderIps() {
        if (!state.bucket) return;
        const rows = filteredIpRows();
        const pageSize = Number($('ip_page_size').value) || 100;
        const pages = Math.max(1, Math.ceil(rows.length / pageSize));
        state.ipPage = Math.min(state.ipPage, pages);
        const start = (state.ipPage - 1) * pageSize;
        const totalIps = state.allBucket
            ? Object.keys(state.allBucket.ips).length
            : Object.keys(state.bucket.ips).length;
        $('ip_summary').textContent = rows.length + ' / ' + totalIps + ' IP';
        $('ip_rows').innerHTML = rows.slice(start, start + pageSize).map(([ip, count], index) => {
            const status = ipPolicyStatus(ip);
            const bot = state.bucket.botIps[ip];
            const sourceLabel = bot
                ? bot
                : state.bucket.searchIps[ip] > 0
                    ? '\u641c\u7d22\u6765\u6e90'
                    : state.bucket.userIps[ip] > 0
                        ? '\u7528\u6237\u6765\u6e90'
                        : state.bucket.unknownSourceIps[ip] > 0
                            ? '\u5176\u4ed6\u6765\u6e90'
                            : '';
            const actions = String(ip).includes(':')
                ? '<button class="block-ip btn-xs" data-ip="' + esc(ip) + '" data-bits="128">单IP</button>'
                : '<button class="block-ip btn-xs" data-ip="' + esc(ip) + '" data-bits="24">/24</button>' +
                  '<button class="block-ip btn-xs" data-ip="' + esc(ip) + '" data-bits="16">/16</button>' +
                '<button class="block-ip btn-xs danger" data-ip="' + esc(ip) + '" data-bits="8">/8</button>';
            return '<tr><td>' + (start + index + 1) + '</td><td class="mono ' + (status.blocked ? 'blocked' : '') + '">' +
                esc(ip) + (status.blocked ? '（已封）' : '') +
                (status.allowlisted ? '<span class="tag">白名单</span>' : '') +
                (sourceLabel ? '<span class="tag">' + esc(sourceLabel) + '</span>' : '') +
                '</td><td>' + formatNumber(count) + '</td><td class="nowrap">' +
                '<span class="block-actions">' + actions + '</span></td></tr>';
        }).join('') || '<tr><td colspan="4" class="empty">没有符合条件的 IP</td></tr>';
        document.querySelectorAll('.block-ip').forEach(button => {
            button.onclick = () => addBlock(button.dataset.ip, Number(button.dataset.bits));
        });
        $('ip_pager').innerHTML =
            '<span>第 ' + state.ipPage + '/' + pages + ' 页</span>' +
            '<button id="ip_prev" ' + (state.ipPage <= 1 ? 'disabled' : '') + '>上一页</button>' +
            '<button id="ip_next" ' + (state.ipPage >= pages ? 'disabled' : '') + '>下一页</button>';
        $('ip_prev').onclick = () => {state.ipPage -= 1; renderIps();};
        $('ip_next').onclick = () => {state.ipPage += 1; renderIps();};
    }

    function cacheAgeText(milliseconds) {
        const minutes = Math.max(1, Math.round(milliseconds / 60000));
        if (minutes < 60) return minutes + ' 分钟';
        const hours = Math.round(minutes / 60);
        return hours + ' 小时';
    }

    async function loadSelectedLogs(forceRefresh = false) {
        $('log_progress').style.display = 'block';
        $('log_progress_text').className = '';
        $('log_progress_text').textContent = forceRefresh ? '正在刷新所选日志…' : '正在读取浏览器缓存…';
        try {
            const files = selectedLogFiles();
            if (!files.length) {
                state.logItems = [];
                rebuildBucket();
                $('log_progress').style.display = 'none';
                return;
            }

            if (!forceRefresh) {
                const cached = await NSL.readLogCaches(files);
                if (cached.length === files.length) {
                    state.logItems = cached;
                    rebuildBucket();
                    const oldest = Math.min(...cached.map(item => Number(item.cache.savedAt || 0)));
                    const age = Date.now() - oldest;
                    const promptKey = files.map(file => file.id).sort().join(',');
                    if (age <= 30 * 60 * 1000) {
                        $('log_progress_text').textContent = '已读取浏览器缓存（' + cacheAgeText(age) + '前更新）';
                        $('log_progress_bar').style.width = '100%';
                        setTimeout(() => {$('log_progress').style.display = 'none';}, 700);
                        return;
                    }
                    if (!state.stalePrompted.has(promptKey)) {
                        state.stalePrompted.add(promptKey);
                        const shouldRefresh = confirm(
                            '日志缓存已超过 30 分钟（约 ' + cacheAgeText(age) + '），是否读取新增日志？'
                        );
                        if (!shouldRefresh) {
                            $('log_progress_text').textContent = '继续使用浏览器缓存，未读取服务器新增内容';
                            $('log_progress_bar').style.width = '100%';
                            setTimeout(() => {$('log_progress').style.display = 'none';}, 900);
                            return;
                        }
                    } else {
                        $('log_progress_text').textContent = '继续使用本次打开时选择的缓存';
                        setTimeout(() => {$('log_progress').style.display = 'none';}, 700);
                        return;
                    }
                }
            }

            state.logItems = await NSL.refreshLogCaches(files, (file, offset, size) => {
                $('log_progress_text').textContent = '浏览器解析 ' + file.name + '：' + formatNumber(offset) + ' / ' + formatNumber(size) + ' 字节';
                $('log_progress_bar').style.width = (size ? offset / size * 100 : 100) + '%';
            });
            $('log_progress_text').textContent = '日志浏览器缓存已更新';
            $('log_progress_bar').style.width = '100%';
            setTimeout(() => {$('log_progress').style.display = 'none';}, 900);
            rebuildBucket();
        } catch (error) {
            $('log_progress_text').textContent = error.message;
            $('log_progress_text').className = 'error';
        }
    }

    async function prepareLogs() {
        $('log_progress').style.display = 'block';
        $('log_progress_text').textContent = '读取日志清单…';
        try {
            state.logFiles = await NSL.fetchLogManifest();
            renderLogFileOptions();
            await loadSelectedLogs(false);
        } catch (error) {
            $('log_progress_text').textContent = error.message;
            $('log_progress_text').className = 'error';
        }
    }

    async function nginxAction(path, reloadButton) {
        $('nginx_msg').textContent = '执行中…';
        try {
            const response = await fetch(NSL.apiUrl(path), {cache: 'no-store'});
            const data = await response.json();
            $('nginx_msg').textContent = data.output || '';
            $('nginx_msg').className = data.ok ? 'ok' : 'error';
            if (reloadButton) $('nginx_reload').disabled = !data.ok;
        } catch (error) {
            $('nginx_msg').textContent = error.message;
            $('nginx_msg').className = 'error';
        }
    }

    document.querySelectorAll('.tab[data-list]').forEach(button => {
        button.onclick = () => loadList(button.dataset.list);
    });
    $('add_rule').onclick = addRule;
    $('new_rule').onkeydown = event => {if (event.key === 'Enter') addRule();};
    $('save_list').onclick = saveList;
    $('undo_list').onclick = () => setListContent(state.configs[state.activeList].savedContent);
    $('rule_search').oninput = () => {rememberControl('rule_search'); state.rulePage = 1; renderList();};
    $('list_content').oninput = () => {updateDirty(); scheduleAnalysis();};
    $('refresh_logs').onclick = () => loadSelectedLogs(true);
    $('log_file').onchange = () => {
        NSL.save('ui_log_file', $('log_file').value);
        loadSelectedLogs(false);
    };
    $('status_scope').onchange = () => {rememberControl('status_scope'); rebuildBucket();};
    $('ip_min').oninput = () => {rememberControl('ip_min'); state.ipPage = 1; renderIps();};
    $('ip_scope').onchange = () => {rememberControl('ip_scope'); state.ipPage = 1; renderIps();};
    $('source_scope').onchange = () => {rememberControl('source_scope'); state.ipPage = 1; renderIps();};
    $('hide_bots').onchange = () => {rememberControl('hide_bots'); renderIps();};
    $('ip_sort').onchange = () => {rememberControl('ip_sort'); state.ipPage = 1; renderIps();};
    $('ip_page_size').onchange = () => {rememberControl('ip_page_size'); state.ipPage = 1; renderIps();};
    $('rule_page_size').onchange = () => {rememberControl('rule_page_size'); state.rulePage = 1; renderList();};
    $('ip_export').onclick = exportIps;
    $('list_export').onclick = exportList;
    $('ip_expand').onclick = () => toggleExpanded('ip_expand', 'ip_scroll');
    $('rule_expand').onclick = () => toggleExpanded('rule_expand', 'rule_scroll');
    $('nginx_test').onclick = () => nginxAction('/api/nginx_test', true);
    $('nginx_reload').onclick = () => nginxAction('/api/nginx_reload', false);

    (async () => {
        await ensureLists();
        await prepareLogs();
    })();
})();
