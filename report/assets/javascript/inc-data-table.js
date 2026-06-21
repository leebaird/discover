(function () {
    var IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

    function isIPv4(value) {
        if (!IPV4_RE.test(value)) {
            return false;
        }

        return value.split('.').every(function (part) {
            var octet = Number(part);
            return octet >= 0 && octet <= 255;
        });
    }

    function compareIPv4(aVal, bVal) {
        var aParts = aVal.split('.').map(Number);
        var bParts = bVal.split('.').map(Number);
        var i;

        for (i = 0; i < 4; i++) {
            if (aParts[i] !== bParts[i]) {
                return aParts[i] - bParts[i];
            }
        }

        return 0;
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

        if (isIPv4(aVal) && isIPv4(bVal)) {
            return compareIPv4(aVal, bVal);
        }

        return aVal.localeCompare(bVal, undefined, { sensitivity: 'base' });
    }

    function sortTable(table, colIndex, dir) {
        var tbody = table.tBodies[0];
        if (!tbody) {
            return;
        }

        var rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (a, b) {
            var aVal = a.cells[colIndex].textContent.trim();
            var bVal = b.cells[colIndex].textContent.trim();
            var cmp = compareValues(aVal, bVal);

            if (cmp !== 0) {
                return dir * cmp;
            }

            if (colIndex === 0 && a.cells.length > 1 && b.cells.length > 1) {
                var aSub = a.cells[1].textContent.trim();
                var bSub = b.cells[1].textContent.trim();
                return dir * compareValues(aSub, bSub);
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
            table.closest('.inc-names-page')
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