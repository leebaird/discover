(function () {
    function findRowByFirstCell(section, text) {
        if (!section) {
            return null;
        }

        var rows = section.querySelectorAll('tbody tr');
        var i;
        var cell;

        for (i = 0; i < rows.length; i++) {
            cell = rows[i].cells[0];
            if (cell && cell.textContent.trim() === text) {
                return rows[i];
            }
        }

        return null;
    }

    function alignStatusWithLegacy() {
        var statusSection = document.querySelector('.inc-active-section--status');
        var categorySection = document.querySelector('.inc-active-section--categories');
        var statusRow;
        var legacyRow;
        var delta;

        if (!statusSection || !categorySection) {
            return;
        }

        statusRow = findRowByFirstCell(statusSection, '200');
        legacyRow = findRowByFirstCell(categorySection, 'Legacy');
        if (!statusRow || !legacyRow) {
            statusSection.style.marginTop = '';
            return;
        }

        // Measure from a clean baseline so repeated runs stay stable.
        statusSection.style.marginTop = '0px';
        delta = legacyRow.getBoundingClientRect().top - statusRow.getBoundingClientRect().top;

        if (Math.abs(delta) < 0.5) {
            statusSection.style.marginTop = '';
            return;
        }

        statusSection.style.marginTop = delta + 'px';
    }

    function scheduleAlign() {
        window.requestAnimationFrame(function () {
            window.requestAnimationFrame(alignStatusWithLegacy);
        });
    }

    scheduleAlign();
    window.addEventListener('load', scheduleAlign);
    window.addEventListener('resize', scheduleAlign);

    // Re-align after column sorts change row order.
    document.querySelectorAll(
        '.inc-active-section--status .inc-sortable, .inc-active-section--categories .inc-sortable'
    ).forEach(function (el) {
        el.addEventListener('click', scheduleAlign);
        el.addEventListener('keydown', function (event) {
            if (event.key === 'Enter' || event.key === ' ') {
                scheduleAlign();
            }
        });
    });
})();
