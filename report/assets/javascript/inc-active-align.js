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

    /** Shared Count column width (px). Must match modern.css .inc-active-count. */
    var ACTIVE_COUNT_WIDTH_PX = 72;

    /**
     * Force every Active Count cell to the same px width.
     * Needed after CMS frame stretch — table-layout alone can still redistribute.
     */
    function pinActiveCountColumns() {
        var cells = document.querySelectorAll(
            '.inc-active-page .inc-active-column .inc-data-table th.inc-active-count, ' +
            '.inc-active-page .inc-active-column .inc-data-table td.inc-active-count'
        );
        var i;
        var px = ACTIVE_COUNT_WIDTH_PX + 'px';

        for (i = 0; i < cells.length; i++) {
            cells[i].style.width = px;
            cells[i].style.minWidth = px;
            cells[i].style.maxWidth = px;
            cells[i].style.boxSizing = 'border-box';
        }
    }

    /**
     * Stretch target frame to match source frame outer width (px).
     * Source layout is never modified. Count stays shared px via pin.
     */
    function matchFrameWidth(sourceSectionSel, targetSectionSel) {
        var sourceSection = document.querySelector(sourceSectionSel);
        var targetSection = document.querySelector(targetSectionSel);
        if (!sourceSection || !targetSection) {
            return;
        }

        var sourceFrame = sourceSection.querySelector('.inc-content-frame--table');
        var targetFrame = targetSection.querySelector('.inc-content-frame--table');
        if (!sourceFrame || !targetFrame) {
            return;
        }

        // Reset target only — never touch source sizing.
        targetFrame.style.width = '';

        var w = Math.ceil(sourceFrame.getBoundingClientRect().width);
        if (w < 1) {
            return;
        }

        targetFrame.style.width = w + 'px';
    }

    function matchCmsWidthToCategory() {
        matchFrameWidth('.inc-active-section--categories', '.inc-active-section--cms');
    }

    /**
     * Make Technology label column the same px width as Web Server label.
     * Web Servers layout is never modified.
     */
    function matchTechnologiesWidthToWebservers() {
        var wsSection = document.querySelector('.inc-active-section--webservers');
        var techSection = document.querySelector('.inc-active-section--technologies');
        if (!wsSection || !techSection) {
            return;
        }

        var wsFrame = wsSection.querySelector('.inc-content-frame--table');
        var techFrame = techSection.querySelector('.inc-content-frame--table');
        var wsLabel = wsSection.querySelector('thead th:first-child');
        var techLabels = techSection.querySelectorAll(
            'thead th:first-child, tbody td:first-child'
        );
        var i;
        var labelW;
        var frameW;
        var px;

        if (!wsFrame || !techFrame || !wsLabel || !techLabels.length) {
            return;
        }

        // Reset tech only so measurements stay stable across re-runs.
        techFrame.style.width = '';
        for (i = 0; i < techLabels.length; i++) {
            techLabels[i].style.width = '';
            techLabels[i].style.minWidth = '';
            techLabels[i].style.maxWidth = '';
        }

        labelW = Math.ceil(wsLabel.getBoundingClientRect().width);
        frameW = Math.ceil(wsFrame.getBoundingClientRect().width);
        if (labelW < 1 || frameW < 1) {
            return;
        }

        // Outer frame matches Web Servers; Count stays pinned at 72px.
        techFrame.style.width = frameW + 'px';

        // Pin Technology column to Web Server column width (px, not rem).
        px = labelW + 'px';
        for (i = 0; i < techLabels.length; i++) {
            techLabels[i].style.width = px;
            techLabels[i].style.minWidth = px;
            techLabels[i].style.maxWidth = px;
            techLabels[i].style.boxSizing = 'border-box';
        }
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

    function runAlign() {
        pinActiveCountColumns();
        matchCmsWidthToCategory();
        matchTechnologiesWidthToWebservers();
        // Re-pin after frame stretch so Count does not absorb free width.
        pinActiveCountColumns();
        alignStatusWithLegacy();
    }

    function scheduleAlign() {
        window.requestAnimationFrame(function () {
            window.requestAnimationFrame(runAlign);
        });
    }

    // Align once after initial table sorts, and again on resize/load.
    // Do not re-align on column sort clicks — that moves rows and caused
    // the status table to jump up over the Scope section.
    scheduleAlign();
    window.addEventListener('load', scheduleAlign);
    window.addEventListener('resize', scheduleAlign);
})();
