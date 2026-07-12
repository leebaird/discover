(function () {
    var IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
    var SRV_VALUE_RE = /→\s*([^:\s]+)(?::\d+)?\s*$/;
    var SORT_TYPE_ORDER = { ipv4: 0, ipv6: 1, integer: 2, text: 3 };

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

    function parseInteger(value) {
        var normalized = value.trim().replace(/,/g, '');

        if (/^\d+$/.test(normalized)) {
            return parseInt(normalized, 10);
        }

        return null;
    }

    function sortKey(value) {
        var candidate = value.trim();
        var integerValue = parseInteger(candidate);
        var srvMatch = candidate.match(SRV_VALUE_RE);

        if (integerValue !== null) {
            return {
                type: 'integer',
                value: integerValue
            };
        }

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

        if (aKey.type === 'integer') {
            return aKey.value - bKey.value;
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

    function getSortables(table) {
        return table.querySelectorAll('thead .inc-sortable');
    }

    function getSortCol(sortableEl) {
        var attr = sortableEl.getAttribute('data-sort-col');
        var th;

        if (attr !== null && attr !== '') {
            return parseInt(attr, 10);
        }

        if (sortableEl.tagName === 'TH') {
            return sortableEl.cellIndex;
        }

        th = sortableEl.closest('th');
        return th ? th.cellIndex : -1;
    }

    function getSortField(sortableEl) {
        return sortableEl.getAttribute('data-sort-field') || '';
    }

    function getCellSortValue(cell, sortField) {
        var fieldEl;
        var value;

        if (!cell) {
            return '';
        }

        if (sortField) {
            fieldEl = cell.querySelector('[data-sort-field="' + sortField + '"]');
            if (!fieldEl) {
                return '';
            }
            value = fieldEl.textContent.trim();
            // Placeholder dash sorts with empty values (last).
            if (value === '-') {
                return '';
            }
            return value;
        }

        return cell.textContent.trim();
    }

    function getTiebreakerCols(sortableEl) {
        var attr = sortableEl.getAttribute('data-sort-then');

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

    function sortTable(table, colIndex, dir, sortField, tiebreakers) {
        var tbody = table.tBodies[0];
        if (!tbody || colIndex < 0) {
            return;
        }

        var rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (a, b) {
            var aCell = a.cells[colIndex];
            var bCell = b.cells[colIndex];
            var aSortLast = aCell && aCell.hasAttribute('data-sort-last');
            var bSortLast = bCell && bCell.hasAttribute('data-sort-last');

            if (aSortLast !== bSortLast) {
                return aSortLast ? 1 : -1;
            }

            var aVal = getCellSortValue(aCell, sortField);
            var bVal = getCellSortValue(bCell, sortField);
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

    function updateHeaders(table, activeEl, dir) {
        getSortables(table).forEach(function (el) {
            el.classList.remove('inc-sort-asc', 'inc-sort-desc');
            el.removeAttribute('aria-sort');
        });

        if (activeEl) {
            activeEl.classList.add(dir === 1 ? 'inc-sort-asc' : 'inc-sort-desc');
            activeEl.setAttribute('aria-sort', dir === 1 ? 'ascending' : 'descending');
        }
    }

    function initTable(table) {
        var state = { el: null, col: -1, field: '', dir: 1 };
        var headers = getSortables(table);
        var defaultCol = table.getAttribute('data-default-col');
        var defaultSortable = null;

        if (defaultCol !== null) {
            state.col = parseInt(defaultCol, 10);
            state.dir = parseInt(table.getAttribute('data-default-dir') || '1', 10);
            headers.forEach(function (el) {
                if (!defaultSortable && getSortCol(el) === state.col && !getSortField(el)) {
                    defaultSortable = el;
                }
            });
            if (!defaultSortable) {
                headers.forEach(function (el) {
                    if (!defaultSortable && getSortCol(el) === state.col) {
                        defaultSortable = el;
                    }
                });
            }
        } else if (headers.length > 0) {
            defaultSortable = headers[0];
            state.col = getSortCol(defaultSortable);
            state.field = getSortField(defaultSortable);
            state.dir = 1;
        }

        if (defaultSortable && state.col >= 0 && !isNaN(state.col)) {
            state.el = defaultSortable;
            state.field = getSortField(defaultSortable);
            sortTable(table, state.col, state.dir, state.field, getTiebreakerCols(defaultSortable));
            updateHeaders(table, state.el, state.dir);
        }

        headers.forEach(function (el) {
            el.setAttribute('role', 'button');
            el.setAttribute('tabindex', '0');

            function activate() {
                var col = getSortCol(el);
                var field = getSortField(el);

                if (state.el === el) {
                    state.dir *= -1;
                } else {
                    state.el = el;
                    state.col = col;
                    state.field = field;
                    state.dir = 1;
                }

                sortTable(table, col, state.dir, field, getTiebreakerCols(el));
                updateHeaders(table, state.el, state.dir);
            }

            el.addEventListener('click', function (event) {
                event.stopPropagation();
                activate();
            });
            el.addEventListener('keydown', function (event) {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    event.stopPropagation();
                    activate();
                }
            });
        });
    }

    document.querySelectorAll('table.inc-data-table').forEach(initTable);
})();
