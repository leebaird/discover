(function () {
    var IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
    var SRV_VALUE_RE = /→\s*([^:\s]+)(?::\d+)?\s*$/;
    var SORT_TYPE_ORDER = { ipv4: 0, ipv6: 1, text: 2 };

    function isIPv4(value) {
        if (!IPV4_RE.test(value)) {
            return false;
        }

        return value.split('.').every(function (part) {
            var octet = Number(part);
            return octet >= 0 && octet <= 255;
        });
    }

    function parseIPv6Groups(value) {
        var normalized = value.trim().toLowerCase();
        var halves = normalized.split('::');
        var head;
        var tail;
        var groups;
        var missing;
        var i;

        if (!normalized || halves.length > 2) {
            return null;
        }

        function parsePart(part) {
            var pieces;
            var piece;
            var octets;
            var partGroups = [];
            var j;

            if (!part) {
                return [];
            }

            pieces = part.split(':');
            for (j = 0; j < pieces.length; j++) {
                piece = pieces[j];
                if (!piece) {
                    return null;
                }

                if (piece.indexOf('.') !== -1) {
                    if (!isIPv4(piece)) {
                        return null;
                    }

                    octets = piece.split('.').map(Number);
                    partGroups.push((octets[0] << 8) | octets[1], (octets[2] << 8) | octets[3]);
                    return partGroups;
                }

                partGroups.push(parseInt(piece, 16));
            }

            return partGroups;
        }

        head = parsePart(halves[0]);
        if (head === null) {
            return null;
        }

        if (halves.length === 1) {
            if (head.length !== 8) {
                return null;
            }

            groups = head;
        } else {
            tail = parsePart(halves[1]);
            if (tail === null) {
                return null;
            }

            missing = 8 - head.length - tail.length;
            if (missing < 0) {
                return null;
            }

            groups = head.concat(new Array(missing).fill(0), tail);
        }

        if (groups.length !== 8) {
            return null;
        }

        for (i = 0; i < groups.length; i++) {
            if (isNaN(groups[i]) || groups[i] < 0 || groups[i] > 0xffff) {
                return null;
            }
        }

        return groups;
    }

    function compareParts(parts, length) {
        var i;

        for (i = 0; i < length; i++) {
            if (parts[0][i] !== parts[1][i]) {
                return parts[0][i] - parts[1][i];
            }
        }

        return 0;
    }

    function sortKey(value) {
        var candidate = value.trim();
        var srvMatch = candidate.match(SRV_VALUE_RE);

        if (srvMatch) {
            candidate = srvMatch[1];
        }

        if (isIPv4(candidate)) {
            return {
                type: 'ipv4',
                parts: candidate.split('.').map(Number)
            };
        }

        candidate = parseIPv6Groups(candidate);
        if (candidate) {
            return {
                type: 'ipv6',
                parts: candidate
            };
        }

        return {
            type: 'text',
            text: value
        };
    }

    function compareSortKeys(aKey, bKey) {
        if (aKey.type !== bKey.type) {
            return SORT_TYPE_ORDER[aKey.type] - SORT_TYPE_ORDER[bKey.type];
        }

        if (aKey.type === 'ipv4') {
            return compareParts([aKey.parts, bKey.parts], 4);
        }

        if (aKey.type === 'ipv6') {
            return compareParts([aKey.parts, bKey.parts], 8);
        }

        return aKey.text.localeCompare(bKey.text, undefined, { sensitivity: 'base' });
    }

    function compareValues(aVal, bVal) {
        if (aVal === bVal) {
            return 0;
        }

        if (!aVal) {
            return 1;
        }

        if (!bVal) {
            return -1;
        }

        return compareSortKeys(sortKey(aVal), sortKey(bVal));
    }

    function getTiebreakerCols(table, colIndex) {
        var headers = table.querySelectorAll('thead th.inc-sortable');
        var header = headers[colIndex];
        var attr;

        if (!header) {
            return null;
        }

        attr = header.getAttribute('data-sort-then');
        if (!attr) {
            return null;
        }

        return attr.split(',').map(function (part) {
            return parseInt(part.trim(), 10);
        }).filter(function (index) {
            return !isNaN(index);
        });
    }

    function compareTiebreakers(a, b, tiebreakers, dir) {
        var i;
        var tieCol;
        var tieCmp;

        for (i = 0; i < tiebreakers.length; i++) {
            tieCol = tiebreakers[i];
            if (tieCol >= a.cells.length || tieCol >= b.cells.length) {
                continue;
            }

            tieCmp = compareValues(
                a.cells[tieCol].textContent.trim(),
                b.cells[tieCol].textContent.trim()
            );
            if (tieCmp !== 0) {
                return dir * tieCmp;
            }
        }

        return 0;
    }

    function sortTable(table, colIndex, dir) {
        var tbody = table.tBodies[0];
        if (!tbody) {
            return;
        }

        var tiebreakers = getTiebreakerCols(table, colIndex);
        var rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (a, b) {
            var aVal = a.cells[colIndex].textContent.trim();
            var bVal = b.cells[colIndex].textContent.trim();
            var cmp = compareValues(aVal, bVal);

            if (cmp !== 0) {
                return dir * cmp;
            }

            if (tiebreakers && tiebreakers.length) {
                return compareTiebreakers(a, b, tiebreakers, dir);
            }

            if (a.cells.length > 1 && b.cells.length > 1) {
                var secondaryCol = colIndex === 1 ? 0 : 1;
                var aSub = a.cells[secondaryCol].textContent.trim();
                var bSub = b.cells[secondaryCol].textContent.trim();
                var subCmp = compareValues(aSub, bSub);

                if (subCmp !== 0) {
                    return dir * subCmp;
                }
            }

            return 0;
        });

        rows.forEach(function (row) {
            tbody.appendChild(row);
        });
    }

    function updateHeaders(table, activeCol, dir) {
        var headers = table.querySelectorAll('thead th.inc-sortable');
        headers.forEach(function (th, index) {
            th.classList.remove('inc-sort-asc', 'inc-sort-desc');
            th.removeAttribute('aria-sort');
            if (index === activeCol) {
                th.classList.add(dir === 1 ? 'inc-sort-asc' : 'inc-sort-desc');
                th.setAttribute('aria-sort', dir === 1 ? 'ascending' : 'descending');
            }
        });
    }

    function initTable(table) {
        var state = { col: -1, dir: 1 };
        var headers = table.querySelectorAll('thead th.inc-sortable');
        var defaultCol = table.getAttribute('data-default-col');

        if (defaultCol !== null) {
            state.col = parseInt(defaultCol, 10);
            state.dir = parseInt(table.getAttribute('data-default-dir') || '1', 10);
        } else if (
            table.closest('.inc-subdomains-tables') ||
            table.closest('.inc-registered-domains-page') ||
            table.closest('.inc-squatting-page') ||
            table.closest('.inc-emails-page') ||
            table.closest('.inc-names-page') ||
            table.closest('.inc-records-page')
        ) {
            state.col = 0;
            state.dir = 1;
        }

        if (state.col >= 0 && !isNaN(state.col) && state.col < headers.length) {
            sortTable(table, state.col, state.dir);
            updateHeaders(table, state.col, state.dir);
        }

        headers.forEach(function (th, colIndex) {
            th.setAttribute('role', 'button');
            th.setAttribute('tabindex', '0');

            function activate() {
                if (state.col === colIndex) {
                    state.dir *= -1;
                } else {
                    state.col = colIndex;
                    state.dir = 1;
                }
                sortTable(table, colIndex, state.dir);
                updateHeaders(table, state.col, state.dir);
            }

            th.addEventListener('click', activate);
            th.addEventListener('keydown', function (event) {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    activate();
                }
            });
        });
    }

    document.querySelectorAll('table.inc-data-table').forEach(initTable);
})();