/**
 * SOC Agent - Report Generator Modal
 * Componente para generar reportes PDF/DOCX desde sesiones
 */

// Agregar este código al final de chat.html o en un archivo separado

// HTML del modal (agregar antes de </body>)
const reportModalHTML = `
<div id="report-modal" class="fixed inset-0 bg-black bg-opacity-50 hidden z-50 flex items-center justify-center">
    <div class="bg-white rounded-lg shadow-xl max-w-lg w-full mx-4">
        <div class="p-4 border-b flex justify-between items-center">
            <h3 class="text-lg font-bold"><i class="fas fa-file-alt text-indigo-600 mr-2"></i>Generar Reporte</h3>
            <button onclick="hideReportModal()" class="text-gray-500 hover:text-gray-700">
                <i class="fas fa-times text-xl"></i>
            </button>
        </div>
        
        <div class="p-4">
            <!-- Preview Section -->
            <div id="report-preview" class="mb-4 p-3 bg-gray-50 rounded-lg">
                <div class="flex justify-between items-center mb-2">
                    <span class="font-semibold text-sm">Vista Previa</span>
                    <span id="report-session-id" class="text-xs text-gray-500">Sesión: -</span>
                </div>
                <div class="grid grid-cols-2 gap-2 text-sm">
                    <div><span class="text-gray-500">IOCs:</span> <span id="preview-iocs" class="font-bold">0</span></div>
                    <div><span class="text-gray-500">Críticos:</span> <span id="preview-critical" class="font-bold text-red-600">0</span></div>
                    <div><span class="text-gray-500">Altos:</span> <span id="preview-high" class="font-bold text-orange-600">0</span></div>
                    <div><span class="text-gray-500">MITRE:</span> <span id="preview-mitre" class="font-bold">0</span></div>
                </div>
            </div>
            
            <!-- Format Selection -->
            <div class="space-y-3">
                <p class="text-sm text-gray-600 mb-3">Selecciona el formato del reporte:</p>
                
                <button onclick="generateReport('pdf')" class="w-full p-4 border-2 border-gray-200 rounded-lg hover:border-red-500 hover:bg-red-50 transition-all flex items-center gap-4 group">
                    <div class="w-12 h-12 bg-red-100 rounded-lg flex items-center justify-center group-hover:bg-red-200">
                        <i class="fas fa-file-pdf text-2xl text-red-600"></i>
                    </div>
                    <div class="text-left flex-1">
                        <div class="font-bold text-gray-800">PDF</div>
                        <div class="text-xs text-gray-500">Documento profesional con formato visual</div>
                    </div>
                    <i class="fas fa-download text-gray-400 group-hover:text-red-600"></i>
                </button>
                
                <button onclick="generateReport('docx')" class="w-full p-4 border-2 border-gray-200 rounded-lg hover:border-blue-500 hover:bg-blue-50 transition-all flex items-center gap-4 group">
                    <div class="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center group-hover:bg-blue-200">
                        <i class="fas fa-file-word text-2xl text-blue-600"></i>
                    </div>
                    <div class="text-left flex-1">
                        <div class="font-bold text-gray-800">Word (DOCX)</div>
                        <div class="text-xs text-gray-500">Documento editable de Microsoft Word</div>
                    </div>
                    <i class="fas fa-download text-gray-400 group-hover:text-blue-600"></i>
                </button>
                
                <button onclick="generateReport('json')" class="w-full p-4 border-2 border-gray-200 rounded-lg hover:border-green-500 hover:bg-green-50 transition-all flex items-center gap-4 group">
                    <div class="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center group-hover:bg-green-200">
                        <i class="fas fa-file-code text-2xl text-green-600"></i>
                    </div>
                    <div class="text-left flex-1">
                        <div class="font-bold text-gray-800">JSON</div>
                        <div class="text-xs text-gray-500">Datos estructurados para integración</div>
                    </div>
                    <i class="fas fa-download text-gray-400 group-hover:text-green-600"></i>
                </button>
                
                <button onclick="generateReport('markdown')" class="w-full p-4 border-2 border-gray-200 rounded-lg hover:border-gray-500 hover:bg-gray-100 transition-all flex items-center gap-4 group">
                    <div class="w-12 h-12 bg-gray-200 rounded-lg flex items-center justify-center group-hover:bg-gray-300">
                        <i class="fas fa-file-alt text-2xl text-gray-600"></i>
                    </div>
                    <div class="text-left flex-1">
                        <div class="font-bold text-gray-800">Markdown</div>
                        <div class="text-xs text-gray-500">Texto legible para documentación</div>
                    </div>
                    <i class="fas fa-download text-gray-400 group-hover:text-gray-600"></i>
                </button>
            </div>
        </div>
        
        <!-- Loading State -->
        <div id="report-loading" class="hidden p-8 text-center">
            <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-indigo-600 mx-auto mb-4"></div>
            <p class="text-gray-600">Generando reporte...</p>
            <p class="text-xs text-gray-400 mt-1">Esto puede tomar unos segundos</p>
        </div>
        
        <div class="p-4 border-t bg-gray-50 flex justify-between items-center">
            <label class="flex items-center gap-2 text-sm text-gray-600">
                <input type="checkbox" id="include-api-details" class="rounded">
                <span>Incluir datos técnicos de APIs</span>
            </label>
            <button onclick="hideReportModal()" class="btn btn-outline">Cancelar</button>
        </div>
    </div>
</div>
`;

// Funciones JavaScript
function showReportModal() {
    if (!currentSession) {
        showNotification('No hay sesión activa', 'error');
        return;
    }
    
    // Insertar modal si no existe
    if (!document.getElementById('report-modal')) {
        document.body.insertAdjacentHTML('beforeend', reportModalHTML);
    }
    
    document.getElementById('report-modal').classList.remove('hidden');
    loadReportPreview();
}

function hideReportModal() {
    document.getElementById('report-modal').classList.add('hidden');
}

async function loadReportPreview() {
    if (!currentSession) return;
    
    try {
        const response = await fetch(`/api/v2/reports/session/${currentSession.id}/preview`);
        const data = await response.json();
        
        if (data.success) {
            const p = data.preview;
            document.getElementById('report-session-id').textContent = `Sesión: ${p.session.id}`;
            document.getElementById('preview-iocs').textContent = p.statistics.total_iocs;
            document.getElementById('preview-critical').textContent = p.statistics.critical_count;
            document.getElementById('preview-high').textContent = p.statistics.high_count;
            document.getElementById('preview-mitre').textContent = p.mitre_techniques.length;
        }
    } catch (error) {
        console.error('Error loading preview:', error);
    }
}

async function generateReport(format) {
    if (!currentSession) return;
    
    const contentDiv = document.querySelector('#report-modal > div > div:nth-child(2)');
    const loadingDiv = document.getElementById('report-loading');
    const footerDiv = document.querySelector('#report-modal > div > div:last-child');
    
    // Mostrar loading
    contentDiv.classList.add('hidden');
    footerDiv.classList.add('hidden');
    loadingDiv.classList.remove('hidden');
    
    try {
        const includeDetails = document.getElementById('include-api-details')?.checked || false;
        
        let url, filename, mimeType;
        
        switch (format) {
            case 'pdf':
                url = `/api/v2/reports/session/${currentSession.id}/pdf?include_api_details=${includeDetails}`;
                filename = `soc_report_${currentSession.id}.pdf`;
                mimeType = 'application/pdf';
                break;
            case 'docx':
                url = `/api/v2/reports/session/${currentSession.id}/docx?include_api_details=${includeDetails}`;
                filename = `soc_report_${currentSession.id}.docx`;
                mimeType = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
                break;
            case 'json':
                url = `/api/v2/sessions/${currentSession.id}/export?format=json`;
                filename = `session_${currentSession.id}.json`;
                mimeType = 'application/json';
                break;
            case 'markdown':
                url = `/api/v2/sessions/${currentSession.id}/export?format=markdown`;
                filename = `session_${currentSession.id}.md`;
                mimeType = 'text/markdown';
                break;
        }
        
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error('Error generando reporte');
        }
        
        // Descargar archivo
        const blob = await response.blob();
        const downloadUrl = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = downloadUrl;
        a.download = filename;
        a.click();
        URL.revokeObjectURL(downloadUrl);
        
        hideReportModal();
        showNotification(`Reporte ${format.toUpperCase()} generado`, 'success');
        
    } catch (error) {
        console.error('Error generating report:', error);
        showNotification('Error generando reporte', 'error');
    } finally {
        // Restaurar UI
        contentDiv.classList.remove('hidden');
        footerDiv.classList.remove('hidden');
        loadingDiv.classList.add('hidden');
    }
}

// Exportar función para uso global
window.showReportModal = showReportModal;
window.hideReportModal = hideReportModal;
window.generateReport = generateReport;
