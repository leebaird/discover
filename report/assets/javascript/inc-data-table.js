(function () {
    function sortTable(table, colIndex, dir) {
        var tbody = table.tBodies[0];
        if (!tbody) {
            return;
        }

        var rows = Array.prototype.slice.call(tbody.rows);
        rows.sort(function (a, b) {
            var aVal = a.cells[colIndex].textContent.trim();
            var bVal = b.cells[colIndex].textContent.trim();
            return dir * aVal.localeCompare(bVal, undefined, { sensitivity: 'base' });
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