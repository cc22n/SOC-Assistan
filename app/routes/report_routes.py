"""
API Endpoints para Reportes
SOC Agent - Fase 2

Endpoints:
- GET /api/v2/reports/session/{id}/pdf - Generar reporte PDF
- GET /api/v2/reports/session/{id}/docx - Generar reporte DOCX
- GET /api/v2/reports/session/{id}/preview - Vista previa del reporte (JSON)
- POST /api/v2/reports/analysis/{id}/pdf - Reporte de un análisis específico
"""
from flask import Blueprint, request, jsonify, send_file
from flask_login import login_required, current_user
from app.services.report_generator import report_generator
from app.services.session_manager import session_manager
from app.models.ioc import IOC, IOCAnalysis, db
import logging
from app.utils.time_utils import utcnow
from io import BytesIO

from app.utils.responses import safe_error_response
from app.utils.pdf_safe import esc
from app.utils.analysis_access import authorized_analysis as _authorized_analysis

logger = logging.getLogger(__name__)

# Crear blueprint
bp = Blueprint('reports', __name__, url_prefix='/api/v2/reports')


@bp.route('/session/<int:session_id>/pdf', methods=['GET'])
@login_required
def generate_session_pdf(session_id):
    """
    Genera reporte PDF de una sesión de investigación.
    
    GET /api/v2/reports/session/123/pdf
    Query params:
        - include_api_details: bool (default: false)
    """
    try:
        # Verificar permisos
        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        
        if not session.is_visible_to(current_user):
            return jsonify({'error': 'No autorizado'}), 403
        
        include_details = request.args.get('include_api_details', 'false').lower() == 'true'
        
        # Generar PDF
        pdf_buffer = report_generator.generate_pdf(session_id, include_api_details=include_details)
        
        if not pdf_buffer:
            return jsonify({'error': 'Error generando PDF'}), 500
        
        # Generar nombre del archivo
        title_slug = (session.title or 'investigation').replace(' ', '_')[:30]
        filename = f"soc_report_{title_slug}_{session_id}.pdf"
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return safe_error_response(e, "Error generating PDF report")


@bp.route('/session/<int:session_id>/docx', methods=['GET'])
@login_required
def generate_session_docx(session_id):
    """
    Genera reporte DOCX de una sesión de investigación.
    
    GET /api/v2/reports/session/123/docx
    Query params:
        - include_api_details: bool (default: false)
    """
    try:
        # Verificar permisos
        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        
        if not session.is_visible_to(current_user):
            return jsonify({'error': 'No autorizado'}), 403
        
        include_details = request.args.get('include_api_details', 'false').lower() == 'true'
        
        # Generar DOCX
        docx_buffer = report_generator.generate_docx(session_id, include_api_details=include_details)
        
        if not docx_buffer:
            return jsonify({'error': 'Error generando DOCX'}), 500
        
        # Generar nombre del archivo
        title_slug = (session.title or 'investigation').replace(' ', '_')[:30]
        filename = f"soc_report_{title_slug}_{session_id}.docx"
        
        return send_file(
            docx_buffer,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return safe_error_response(e, "Error generating DOCX report")


@bp.route('/session/<int:session_id>/preview', methods=['GET'])
@login_required
def preview_session_report(session_id):
    """
    Obtiene datos para vista previa del reporte.
    
    GET /api/v2/reports/session/123/preview
    """
    try:
        # Verificar permisos
        session = session_manager.get_session(session_id)
        if not session:
            return jsonify({'error': 'Sesión no encontrada'}), 404
        
        if not session.is_visible_to(current_user):
            return jsonify({'error': 'No autorizado'}), 403
        
        # Obtener datos
        session_data = session_manager.export_session_json(session_id)
        
        if not session_data:
            return jsonify({'error': 'Error obteniendo datos de sesión'}), 500
        
        # Procesar para preview
        iocs = session_data.get('iocs', [])
        
        preview = {
            'session': {
                'id': session.id,
                'title': session.title,
                'status': session.status,
                'created_at': session.created_at.isoformat() if session.created_at else None,
                'highest_risk_level': session.highest_risk_level,
                'total_iocs': session.total_iocs,
                'total_messages': session.total_messages
            },
            'statistics': {
                'total_iocs': len(iocs),
                'critical_count': sum(1 for i in iocs if i.get('risk_level') == 'CRÍTICO'),
                'high_count': sum(1 for i in iocs if i.get('risk_level') == 'ALTO'),
                'medium_count': sum(1 for i in iocs if i.get('risk_level') == 'MEDIO'),
                'low_count': sum(1 for i in iocs if i.get('risk_level') == 'BAJO'),
                'clean_count': sum(1 for i in iocs if i.get('risk_level') == 'LIMPIO'),
            },
            'iocs_summary': [
                {
                    'value': ioc.get('ioc_value', '')[:50],
                    'type': ioc.get('ioc_type'),
                    'risk_level': ioc.get('risk_level'),
                    'score': ioc.get('confidence_score')
                }
                for ioc in iocs[:10]  # Primeros 10 para preview
            ],
            'mitre_techniques': list(set(
                tech
                for ioc in iocs
                for tech in (ioc.get('analysis_details', {}).get('mitre_techniques') or [])
            )),
            'sources_used': list(set(
                source
                for ioc in iocs
                for source in (ioc.get('analysis_details', {}).get('sources_used') or [])
            )),
            'available_formats': ['pdf', 'docx', 'json', 'markdown']
        }
        
        return jsonify({
            'success': True,
            'preview': preview
        }), 200
        
    except Exception as e:
        return safe_error_response(e, "Error generating preview")


@bp.route('/analysis/<int:analysis_id>/pdf', methods=['GET'])
@login_required
def generate_analysis_pdf(analysis_id):
    """
    Genera reporte PDF de un análisis individual.
    
    GET /api/v2/reports/analysis/456/pdf
    """
    try:
        analysis, denied = _authorized_analysis(analysis_id)
        if denied:
            return denied

        # Generar PDF simple para un solo análisis
        pdf_buffer = _generate_single_analysis_pdf(analysis)
        
        if not pdf_buffer:
            return jsonify({'error': 'Error generando PDF'}), 500
        
        ioc = analysis.ioc
        filename = f"ioc_report_{ioc.ioc_type}_{analysis_id}.pdf"
        
        return send_file(
            pdf_buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename
        )
        
    except Exception as e:
        return safe_error_response(e, "Error generating analysis PDF")


@bp.route('/analysis/<int:analysis_id>/docx', methods=['GET'])
@login_required
def generate_analysis_docx(analysis_id):
    """
    Genera reporte DOCX de un análisis individual.

    GET /api/v2/reports/analysis/456/docx
    La página de análisis ofrecía este formato pero el endpoint no existía (404).
    """
    try:
        analysis, denied = _authorized_analysis(analysis_id)
        if denied:
            return denied

        buffer = _generate_single_analysis_docx(analysis)
        if not buffer:
            return jsonify({'error': 'Error generando DOCX'}), 500

        return send_file(
            buffer,
            mimetype='application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            as_attachment=True,
            download_name=f"ioc_report_{analysis.ioc.ioc_type}_{analysis_id}.docx"
        )
    except Exception as e:
        return safe_error_response(e, "Error generating analysis DOCX")


@bp.route('/formats', methods=['GET'])
@login_required
def get_available_formats():
    """
    Obtiene formatos de reporte disponibles.
    
    GET /api/v2/reports/formats
    """
    return jsonify({
        'success': True,
        'formats': [
            {
                'id': 'pdf',
                'name': 'PDF',
                'description': 'Documento PDF con formato profesional',
                'icon': 'fa-file-pdf',
                'color': 'red',
                'available': True
            },
            {
                'id': 'docx',
                'name': 'Word (DOCX)',
                'description': 'Documento editable de Microsoft Word',
                'icon': 'fa-file-word',
                'color': 'blue',
                'available': True
            },
            {
                'id': 'json',
                'name': 'JSON',
                'description': 'Datos estructurados para integración',
                'icon': 'fa-file-code',
                'color': 'green',
                'available': True
            },
            {
                'id': 'markdown',
                'name': 'Markdown',
                'description': 'Texto legible para documentación',
                'icon': 'fa-file-alt',
                'color': 'gray',
                'available': True
            }
        ]
    }), 200


def _generate_single_analysis_pdf(analysis: IOCAnalysis) -> BytesIO:
    """Genera PDF para un solo análisis"""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor
        from reportlab.lib.enums import TA_CENTER
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter, 
                               rightMargin=0.75*inch, leftMargin=0.75*inch,
                               topMargin=0.75*inch, bottomMargin=0.75*inch)
        
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='Title2',
            parent=styles['Title'],
            fontSize=20,
            textColor=HexColor('#4F46E5'),
            spaceAfter=20,
            alignment=TA_CENTER
        ))
        
        story = []
        ioc = analysis.ioc
        
        # Título
        story.append(Paragraph(f"🔒 Análisis de IOC", styles['Title2']))
        story.append(Paragraph(f"{esc(str(ioc.ioc_type).upper())}: {esc(ioc.value)}", styles['Heading2']))
        story.append(Spacer(1, 0.3*inch))
        
        # Datos principales
        risk_colors = {
            'CRÍTICO': '#DC2626', 'ALTO': '#EA580C', 
            'MEDIO': '#CA8A04', 'BAJO': '#059669', 'LIMPIO': '#2563EB'
        }
        
        data = [
            ['Métrica', 'Valor'],
            ['Tipo', ioc.ioc_type.upper()],
            ['Valor', ioc.value[:60] + ('...' if len(ioc.value) > 60 else '')],
            ['Riesgo', analysis.risk_level],
            ['Score', f"{analysis.confidence_score}/100"],
            ['Fuentes', ', '.join(analysis.sources_used or [])],
            ['Fecha', analysis.created_at.strftime('%Y-%m-%d %H:%M') if analysis.created_at else 'N/A'],
        ]
        
        table = Table(data, colWidths=[2*inch, 4.5*inch])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#4F46E5')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('BACKGROUND', (0, 1), (0, -1), HexColor('#F3F4F6')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('TOPPADDING', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#E5E7EB')),
        ]))
        
        story.append(table)
        story.append(Spacer(1, 0.3*inch))
        
        # LLM Analysis
        if analysis.llm_analysis and isinstance(analysis.llm_analysis, dict):
            story.append(Paragraph("📋 Análisis Detallado", styles['Heading2']))
            
            summary = analysis.llm_analysis.get('executive_summary', '')
            if summary:
                story.append(Paragraph(esc(summary), styles['Normal']))
            
            findings = analysis.llm_analysis.get('key_findings', [])
            if findings:
                story.append(Paragraph("<b>Hallazgos:</b>", styles['Normal']))
                for f in findings:
                    story.append(Paragraph(f"• {esc(f)}", styles['Normal']))
            
            recs = analysis.llm_analysis.get('recommendations', [])
            if recs:
                story.append(Paragraph("<b>Recomendaciones:</b>", styles['Normal']))
                for r in recs:
                    story.append(Paragraph(f"• {esc(r)}", styles['Normal']))
        
        # MITRE
        if analysis.mitre_techniques:
            story.append(Spacer(1, 0.2*inch))
            story.append(Paragraph(
                f"<b>MITRE ATT&amp;CK:</b> {esc(', '.join(str(x) for x in analysis.mitre_techniques))}",
                styles['Normal']
            ))
        
        # Footer
        story.append(Spacer(1, 0.5*inch))
        story.append(Paragraph(
            f"Generado por SOC Agent - {utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            styles['Normal']
        ))
        
        doc.build(story)
        buffer.seek(0)
        return buffer
        
    except Exception as e:
        logger.error(f"Error generating single analysis PDF: {e}")
        return None


def _generate_single_analysis_docx(analysis: IOCAnalysis):
    """Genera DOCX para un solo análisis (mismo contenido que el PDF). python-docx escribe texto plano."""
    try:
        from docx import Document
        from app.utils.pdf_safe import plain

        doc = Document()
        ioc = analysis.ioc
        doc.add_heading('Análisis de IOC', level=0)
        doc.add_heading(f"{plain(str(ioc.ioc_type).upper())}: {plain(ioc.value)}", level=2)

        rows = [
            ('Tipo', plain(str(ioc.ioc_type).upper())),
            ('Valor', plain(ioc.value)),
            ('Riesgo', plain(analysis.risk_level)),
            ('Score', f"{plain(analysis.confidence_score)}/100"),
            ('Fuentes', plain(', '.join(str(x) for x in (analysis.sources_used or [])))),
            ('Fecha', analysis.created_at.strftime('%Y-%m-%d %H:%M') if analysis.created_at else 'N/A'),
        ]
        table = doc.add_table(rows=1, cols=2)
        table.style = 'Table Grid'
        table.rows[0].cells[0].text, table.rows[0].cells[1].text = 'Métrica', 'Valor'
        for k, v in rows:
            cells = table.add_row().cells
            cells[0].text, cells[1].text = k, v

        llm = analysis.llm_analysis if isinstance(analysis.llm_analysis, dict) else None
        if llm:
            doc.add_heading('Análisis Detallado', level=2)
            if llm.get('executive_summary'):
                doc.add_paragraph(plain(llm['executive_summary']))
            for titulo, clave in (('Hallazgos', 'key_findings'), ('Recomendaciones', 'recommendations')):
                items = llm.get(clave) or []
                if items:
                    p = doc.add_paragraph()
                    p.add_run(f'{titulo}:').bold = True
                    for item in items:
                        doc.add_paragraph(plain(item), style='List Bullet')

        if analysis.mitre_techniques:
            p = doc.add_paragraph()
            p.add_run('MITRE ATT&CK: ').bold = True
            p.add_run(plain(', '.join(str(x) for x in analysis.mitre_techniques)))

        doc.add_paragraph(f"Generado por SOC Agent - {utcnow().strftime('%Y-%m-%d %H:%M UTC')}")

        buffer = BytesIO()
        doc.save(buffer)
        buffer.seek(0)
        return buffer
    except Exception as e:
        logger.error(f"Error generando DOCX de análisis: {e}")
        return None
