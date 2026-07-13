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

        // Never pull the status table upward over Scope (negative margin).
        if (delta < 0.5) {
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

    // Align once after initial table sorts, and again on resize/load.
    // Do not re-align on column sort clicks — that moves rows and caused
    // the status table to jump up over the Scope section.
    scheduleAlign();
    window.addEventListener('load', scheduleAlign);
    window.addEventListener('resize', scheduleAlign);
})();
