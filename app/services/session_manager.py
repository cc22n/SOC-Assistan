"""
Session Manager - Gestor de Sesiones de Investigación
SOC Agent - Fase 1.5

Este módulo maneja toda la lógica de negocio para:
- Crear y gestionar sesiones de investigación
- Agregar IOCs y mensajes a sesiones
- Construir contexto para el LLM
- Generar resúmenes comprimidos
- Exportar sesiones
"""
import json
import logging
import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

from flask import current_app
from sqlalchemy import desc

from app import db
from app.models.session import (
    InvestigationSession, 
    SessionIOC, 
    SessionMessage,
    get_active_session_for_user
)
from app.models.ioc import IOC, IOCAnalysis

logger = logging.getLogger(__name__)


class SessionManager:
    """
    Gestor de sesiones de investigación.
    
    Responsabilidades:
    - CRUD de sesiones
    - Manejo de contexto para LLM
    - Compresión de historial
    - Exportación
    """
    
    # Configuración de contexto
    MAX_RECENT_MESSAGES = 20  # Mensajes completos a enviar al LLM
    SUMMARY_THRESHOLD = 20    # Generar resumen después de N mensajes
    MAX_CONTEXT_TOKENS = 4000 # Límite aproximado de tokens de contexto
    
    def __init__(self):
        self.llm_service = None  # Lazy loading
    
    def _get_llm_service(self):
        """Obtiene servicio LLM para generar resúmenes"""
        if self.llm_service is None:
            from app.services.llm_service import LLMService
            self.llm_service = LLMService()
        return self.llm_service
    
    # =========================================================================
    # GESTIÓN DE SESIONES
    # =========================================================================
    
    def get_active_session(self, user_id: int) -> Optional[InvestigationSession]:
        """
        Obtiene la sesión activa del usuario.
        Verifica si ha expirado y la cierra si es necesario.
        """
        session = get_active_session_for_user(user_id)
        
        if session and session.is_expired:
            logger.info(f"Session {session.id} expired, closing automatically")
            self.close_session(session.id)
            return None
        
        return session
    
    def get_or_create_session(
        self, 
        user_id: int, 
        title: str = None,
        ioc_value: str = None,
        ioc_type: str = None
    ) -> Tuple[InvestigationSession, bool]:
        """
        Obtiene sesión activa o crea una nueva.
        
        Args:
            user_id: ID del usuario
            title: Título manual (opcional)
            ioc_value: Valor del IOC para generar título automático
            ioc_type: Tipo del IOC
            
        Returns:
            Tuple (session, is_new): La sesión y si es nueva
        """
        existing = self.get_active_session(user_id)
        
        if existing:
            existing.update_activity()
            db.session.commit()
            return existing, False
        
        # Crear nueva sesión
        new_session = InvestigationSession(
            user_id=user_id,
            status='active'
        )
        
        # Generar título
        if title:
            new_session.title = title
        else:
            new_session.title = new_session.generate_title(ioc_value, ioc_type)
        
        db.session.add(new_session)
        db.session.commit()
        
        logger.info(f"Created new session {new_session.id} for user {user_id}")
        return new_session, True
    
    def create_new_session(
        self, 
        user_id: int, 
        title: str = None,
        close_existing: bool = True
    ) -> InvestigationSession:
        """
        Crea una nueva sesión, opcionalmente cerrando la existente.
        
        Args:
            user_id: ID del usuario
            title: Título de la sesión
            close_existing: Si cerrar la sesión activa existente
        """
        if close_existing:
            existing = self.get_active_session(user_id)
            if existing:
                self.close_session(existing.id)
        
        new_session = InvestigationSession(
            user_id=user_id,
            title=title or InvestigationSession().generate_title(),
            status='active'
        )
        
        db.session.add(new_session)
        db.session.commit()
        
        logger.info(f"Created new session {new_session.id} (forced) for user {user_id}")
        return new_session
    
    def get_session(self, session_id: int) -> Optional[InvestigationSession]:
        """Obtiene una sesión por ID"""
        return InvestigationSession.query.get(session_id)
    
    def get_user_sessions(
        self, 
        user_id: int, 
        status: str = None,
        limit: int = 20
    ) -> List[InvestigationSession]:
        """
        Lista sesiones de un usuario.
        
        Args:
            user_id: ID del usuario
            status: Filtrar por estado (active/closed/etc)
            limit: Máximo de resultados
        """
        query = InvestigationSession.query.filter_by(user_id=user_id)
        
        if status:
            query = query.filter_by(status=status)
        
        return query.order_by(desc(InvestigationSession.last_activity_at)).limit(limit).all()
    
    def update_session(
        self, 
        session_id: int, 
        title: str = None, 
        description: str = None
    ) -> Optional[InvestigationSession]:
        """Actualiza metadatos de una sesión"""
        session = self.get_session(session_id)
        
        if not session:
            return None
        
        if title is not None:
            session.title = title
        if description is not None:
            session.description = description
        
        session.update_activity()
        db.session.commit()
        
        return session
    
    def close_session(self, session_id: int) -> bool:
        """Cierra una sesión"""
        session = self.get_session(session_id)
        
        if not session:
            return False
        
        session.close()
        db.session.commit()
        
        logger.info(f"Session {session_id} closed")
        return True
    
    # =========================================================================
    # GESTIÓN DE IOCs EN SESIÓN
    # =========================================================================
    
    def add_ioc_to_session(
        self,
        session_id: int,
        ioc_id: int,
        analysis_id: int = None,
        role: str = 'analyzed',
        message_id: int = None,
        notes: str = None
    ) -> Optional[SessionIOC]:
        """
        Agrega un IOC a una sesión.
        
        Args:
            session_id: ID de la sesión
            ioc_id: ID del IOC
            analysis_id: ID del análisis (opcional)
            role: Rol del IOC (primary/related/context/analyzed)
            message_id: ID del mensaje que agregó el IOC
            notes: Notas del analista
        """
        # Verificar si ya existe
        existing = SessionIOC.query.filter_by(
            session_id=session_id,
            ioc_id=ioc_id
        ).first()
        
        if existing:
            # Actualizar si ya existe
            if analysis_id:
                existing.analysis_id = analysis_id
            if notes:
                existing.analyst_notes = notes
            db.session.commit()
            return existing
        
        # Crear nuevo
        session_ioc = SessionIOC(
            session_id=session_id,
            ioc_id=ioc_id,
            analysis_id=analysis_id,
            role=role,
            added_by_message_id=message_id,
            analyst_notes=notes
        )
        
        db.session.add(session_ioc)
        db.session.commit()
        
        # Actualizar título si es el primer IOC y no tiene título personalizado
        session = self.get_session(session_id)
        if session and session.total_iocs == 1:
            ioc = IOC.query.get(ioc_id)
            if ioc and 'Nueva investigación' in (session.title or ''):
                session.title = session.generate_title(ioc.value, ioc.ioc_type)
                db.session.commit()
        
        logger.info(f"Added IOC {ioc_id} to session {session_id}")
        return session_ioc
    
    def get_session_iocs(self, session_id: int) -> List[SessionIOC]:
        """Obtiene todos los IOCs de una sesión"""
        return SessionIOC.query.filter_by(session_id=session_id).order_by(SessionIOC.added_at).all()
    
    # =========================================================================
    # GESTIÓN DE MENSAJES
    # =========================================================================
    
    def save_message(
        self,
        session_id: int,
        role: str,
        content: str,
        iocs_mentioned: List[str] = None,
        analysis_triggered: bool = False,
        analysis_id: int = None,
        llm_provider: str = None
    ) -> SessionMessage:
        """
        Guarda un mensaje en la sesión.
        
        Args:
            session_id: ID de la sesión
            role: 'user', 'assistant', o 'system'
            content: Contenido del mensaje
            iocs_mentioned: Lista de IOCs mencionados
            analysis_triggered: Si el mensaje disparó un análisis
            analysis_id: ID del análisis generado
            llm_provider: Proveedor LLM usado (para assistant)
        """
        message = SessionMessage(
            session_id=session_id,
            role=role,
            content=content,
            iocs_mentioned=iocs_mentioned,
            analysis_triggered=analysis_triggered,
            analysis_id=analysis_id,
            llm_provider=llm_provider,
            tokens_estimated=SessionMessage.estimate_tokens(content)
        )
        
        db.session.add(message)
        
        # Actualizar actividad de sesión
        session = self.get_session(session_id)
        if session:
            session.update_activity()
        
        db.session.commit()
        
        # Verificar si necesitamos generar resumen
        self._check_and_compress(session_id)
        
        return message
    
    def get_session_messages(
        self, 
        session_id: int, 
        limit: int = None,
        include_summaries: bool = True
    ) -> List[SessionMessage]:
        """
        Obtiene mensajes de una sesión.
        
        Args:
            session_id: ID de la sesión
            limit: Máximo de mensajes (None = todos)
            include_summaries: Incluir mensajes de resumen
        """
        query = SessionMessage.query.filter_by(session_id=session_id)
        
        if not include_summaries:
            query = query.filter_by(is_summary=False)
        
        query = query.order_by(SessionMessage.created_at)
        
        if limit:
            # Obtener los últimos N mensajes
            query = query.order_by(desc(SessionMessage.created_at)).limit(limit)
            messages = query.all()
            messages.reverse()  # Ordenar cronológicamente
            return messages
        
        return query.all()
    
    # =========================================================================
    # CONSTRUCCIÓN DE CONTEXTO PARA LLM
    # =========================================================================
    
    def build_context_for_llm(self, session_id: int, new_message: str = None) -> str:
        """
        Construye el contexto completo para enviar al LLM.
        
        Incluye:
        1. IOCs analizados en la sesión con sus resultados clave
        2. Resumen comprimido de mensajes antiguos (si existe)
        3. Últimos N mensajes completos
        4. Nuevo mensaje del usuario
        
        Args:
            session_id: ID de la sesión
            new_message: Nuevo mensaje del usuario (opcional)
            
        Returns:
            Prompt con contexto completo
        """
        session = self.get_session(session_id)
        if not session:
            return new_message or ""
        
        context_parts = []
        
        # 1. Header de sesión
        context_parts.append(f"=== SESIÓN DE INVESTIGACIÓN ===")
        context_parts.append(f"Título: {session.title or 'Sin título'}")
        context_parts.append(f"Estado: {session.status}")
        if session.highest_risk_level:
            context_parts.append(f"Riesgo más alto detectado: {session.highest_risk_level}")
        context_parts.append("")
        
        # 2. IOCs analizados en esta sesión
        session_iocs = self.get_session_iocs(session_id)
        if session_iocs:
            context_parts.append("=== IOCs ANALIZADOS EN ESTA SESIÓN ===")
            for sioc in session_iocs:
                ioc_info = self._format_ioc_for_context(sioc)
                if ioc_info:
                    context_parts.append(ioc_info)
            context_parts.append("")
        
        # 3. Resumen comprimido (si existe)
        if session.compressed_summary:
            context_parts.append("=== RESUMEN DE CONVERSACIÓN ANTERIOR ===")
            context_parts.append(session.compressed_summary)
            context_parts.append("")
        
        # 4. Últimos mensajes completos
        recent_messages = self.get_session_messages(
            session_id, 
            limit=self.MAX_RECENT_MESSAGES,
            include_summaries=False
        )
        
        if recent_messages:
            context_parts.append("=== CONVERSACIÓN RECIENTE ===")
            for msg in recent_messages:
                role_label = {
                    'user': 'Usuario',
                    'assistant': 'Analista IA',
                    'system': 'Sistema'
                }.get(msg.role, msg.role)
                context_parts.append(f"{role_label}: {msg.content}")
            context_parts.append("")
        
        # 5. Nuevo mensaje (si se proporciona)
        if new_message:
            context_parts.append("=== NUEVA CONSULTA ===")
            context_parts.append(f"Usuario: {new_message}")
            context_parts.append("")
            context_parts.append("Por favor responde considerando todo el contexto anterior de la investigación.")
        
        return "\n".join(context_parts)
    
    def _format_ioc_for_context(self, session_ioc: SessionIOC) -> Optional[str]:
        """Formatea un IOC para incluir en el contexto"""
        if not session_ioc.ioc:
            return None
        
        ioc = session_ioc.ioc
        analysis = session_ioc.analysis
        
        lines = [f"• {ioc.ioc_type.upper()}: {ioc.value}"]
        
        if analysis:
            lines.append(f"  - Riesgo: {analysis.risk_level}")
            lines.append(f"  - Score: {analysis.confidence_score}/100")
            
            # Agregar hallazgos clave del análisis LLM si existen
            if analysis.llm_analysis:
                llm_data = analysis.llm_analysis
                if isinstance(llm_data, dict):
                    if llm_data.get('executive_summary'):
                        summary = llm_data['executive_summary'][:200]
                        lines.append(f"  - Resumen: {summary}")
                    if llm_data.get('threat_level'):
                        lines.append(f"  - Nivel amenaza: {llm_data['threat_level']}")
        
        if session_ioc.analyst_notes:
            lines.append(f"  - Notas: {session_ioc.analyst_notes}")
        
        return "\n".join(lines)
    
    # =========================================================================
    # COMPRESIÓN Y RESÚMENES
    # =========================================================================
    
    def _check_and_compress(self, session_id: int):
        """
        Verifica si es necesario comprimir mensajes antiguos.
        Se ejecuta automáticamente después de guardar mensajes.
        """
        session = self.get_session(session_id)
        if not session:
            return
        
        # Contar mensajes no-resumen
        message_count = SessionMessage.query.filter_by(
            session_id=session_id,
            is_summary=False
        ).count()
        
        # Si superamos el umbral y no hay resumen reciente
        if message_count > self.SUMMARY_THRESHOLD * 2:
            if not session.summary_updated_at or \
               (datetime.utcnow() - session.summary_updated_at.replace(tzinfo=None)) > timedelta(hours=1):
                self._generate_compressed_summary(session_id)
    
    def _generate_compressed_summary(self, session_id: int):
        """
        Genera un resumen comprimido de los mensajes antiguos.
        """
        session = self.get_session(session_id)
        if not session:
            return
        
        # Obtener mensajes antiguos (excluyendo los últimos N)
        all_messages = self.get_session_messages(session_id, include_summaries=False)
        
        if len(all_messages) <= self.MAX_RECENT_MESSAGES:
            return  # No hay suficientes mensajes para resumir
        
        old_messages = all_messages[:-self.MAX_RECENT_MESSAGES]
        
        # Formatear mensajes para el resumen
        messages_text = "\n".join([
            f"{msg.role}: {msg.content[:500]}" for msg in old_messages
        ])
        
        # Generar resumen con LLM
        prompt = f"""Resume la siguiente conversación de análisis de seguridad SOC.
Mantén los puntos clave: IOCs mencionados, conclusiones, acciones tomadas.
Sé conciso pero informativo (máximo 500 palabras).

CONVERSACIÓN:
{messages_text}

RESUMEN:"""
        
        try:
            llm = self._get_llm_service()
            if llm.provider:
                if llm.provider == 'gemini':
                    result = llm._call_gemini(prompt)
                else:
                    result = llm._call_generic_openai_style(prompt)
                
                if isinstance(result, dict):
                    summary = result.get('analysis') or result.get('content') or str(result)
                else:
                    summary = str(result)
                
                # Guardar resumen
                session.compressed_summary = summary
                session.summary_updated_at = datetime.utcnow()
                db.session.commit()
                
                logger.info(f"Generated compressed summary for session {session_id}")
        
        except Exception as e:
            logger.error(f"Error generating summary for session {session_id}: {e}")
    
    def force_generate_summary(self, session_id: int) -> Optional[str]:
        """Fuerza la generación de un resumen (útil antes de cerrar sesión)"""
        self._generate_compressed_summary(session_id)
        session = self.get_session(session_id)
        return session.compressed_summary if session else None
    
    # =========================================================================
    # EXPORTACIÓN
    # =========================================================================
    
    def export_session_json(self, session_id: int) -> Optional[Dict]:
        """
        Exporta una sesión completa a JSON.
        """
        session = self.get_session(session_id)
        if not session:
            return None
        
        # Obtener IOCs con detalles
        iocs_data = []
        for sioc in self.get_session_iocs(session_id):
            ioc_dict = sioc.to_dict()
            
            # Agregar datos completos del análisis si existe
            if sioc.analysis:
                ioc_dict['analysis_details'] = {
                    'virustotal_data': sioc.analysis.virustotal_data,
                    'abuseipdb_data': sioc.analysis.abuseipdb_data,
                    'greynoise_data': sioc.analysis.greynoise_data,
                    'threatfox_data': sioc.analysis.threatfox_data,
                    'llm_analysis': sioc.analysis.llm_analysis,
                    'mitre_techniques': sioc.analysis.mitre_techniques,
                    'sources_used': sioc.analysis.sources_used
                }
            
            iocs_data.append(ioc_dict)
        
        # Obtener mensajes
        messages_data = [msg.to_dict() for msg in self.get_session_messages(session_id)]
        
        return {
            'export_version': '1.0',
            'export_date': datetime.utcnow().isoformat(),
            'session': session.to_dict(),
            'iocs': iocs_data,
            'messages': messages_data,
            'statistics': {
                'total_iocs': session.total_iocs,
                'total_messages': session.total_messages,
                'highest_risk': session.highest_risk_level,
                'duration_hours': self._calculate_session_duration(session)
            }
        }
    
    def export_session_markdown(self, session_id: int) -> Optional[str]:
        """
        Exporta una sesión a Markdown legible.
        """
        session = self.get_session(session_id)
        if not session:
            return None
        
        lines = []
        
        # Header
        lines.append(f"# {session.title or 'Sesión de Investigación'}")
        lines.append("")
        lines.append(f"**Fecha de inicio:** {session.created_at.strftime('%d %b %Y %H:%M') if session.created_at else 'N/A'}")
        lines.append(f"**Estado:** {session.status}")
        lines.append(f"**Riesgo máximo:** {session.highest_risk_level or 'N/A'}")
        lines.append(f"**Total IOCs:** {session.total_iocs}")
        lines.append(f"**Total mensajes:** {session.total_messages}")
        lines.append("")
        
        # IOCs
        lines.append("## IOCs Analizados")
        lines.append("")
        
        for sioc in self.get_session_iocs(session_id):
            if not sioc.ioc:
                continue
            
            risk_emoji = {
                'CRÍTICO': '🔴',
                'ALTO': '🟠',
                'MEDIO': '🟡',
                'BAJO': '🟢',
                'LIMPIO': '⚪'
            }.get(sioc.analysis.risk_level if sioc.analysis else 'N/A', '⚪')
            
            lines.append(f"### {sioc.ioc.ioc_type.upper()}: `{sioc.ioc.value}`")
            lines.append("")
            
            if sioc.analysis:
                lines.append(f"- **Riesgo:** {risk_emoji} {sioc.analysis.risk_level}")
                lines.append(f"- **Score:** {sioc.analysis.confidence_score}/100")
                lines.append(f"- **Fuentes:** {', '.join(sioc.analysis.sources_used or [])}")
                
                if sioc.analysis.llm_analysis and isinstance(sioc.analysis.llm_analysis, dict):
                    summary = sioc.analysis.llm_analysis.get('executive_summary', '')
                    if summary:
                        lines.append(f"- **Resumen:** {summary}")
            
            if sioc.analyst_notes:
                lines.append(f"- **Notas:** {sioc.analyst_notes}")
            
            lines.append("")
        
        # Conversación
        lines.append("## Conversación")
        lines.append("")
        
        for msg in self.get_session_messages(session_id, include_summaries=False):
            timestamp = msg.created_at.strftime('%H:%M') if msg.created_at else ''
            
            if msg.role == 'user':
                lines.append(f"**[{timestamp}] Usuario:**")
            elif msg.role == 'assistant':
                provider = f" ({msg.llm_provider})" if msg.llm_provider else ""
                lines.append(f"**[{timestamp}] Analista IA{provider}:**")
            else:
                lines.append(f"**[{timestamp}] Sistema:**")
            
            lines.append("")
            lines.append(msg.content)
            lines.append("")
            lines.append("---")
            lines.append("")
        
        # Footer
        lines.append("## Metadatos de Exportación")
        lines.append("")
        lines.append(f"- **Exportado:** {datetime.utcnow().strftime('%d %b %Y %H:%M UTC')}")
        lines.append(f"- **ID de sesión:** {session.uuid}")
        lines.append(f"- **Duración:** {self._calculate_session_duration(session):.1f} horas")
        
        return "\n".join(lines)
    
    def _calculate_session_duration(self, session: InvestigationSession) -> float:
        """Calcula la duración de una sesión en horas"""
        if not session.created_at:
            return 0
        
        end_time = session.closed_at or session.last_activity_at or datetime.utcnow()
        if hasattr(end_time, 'replace'):
            end_time = end_time.replace(tzinfo=None)
        
        start_time = session.created_at
        if hasattr(start_time, 'replace'):
            start_time = start_time.replace(tzinfo=None)
        
        duration = end_time - start_time
        return duration.total_seconds() / 3600
    
    # =========================================================================
    # UTILIDADES
    # =========================================================================
    
    def close_expired_sessions(self) -> int:
        """
        Cierra todas las sesiones expiradas.
        Ejecutar periódicamente (ej: cada hora con Celery).
        """
        from app.models.session import close_expired_sessions
        return close_expired_sessions()
    
    def get_session_summary_for_ui(self, session_id: int) -> Dict:
        """
        Obtiene un resumen rápido de la sesión para mostrar en la UI.
        """
        session = self.get_session(session_id)
        if not session:
            return {}
        
        # Obtener IOCs resumidos
        iocs_summary = []
        for sioc in self.get_session_iocs(session_id)[:5]:  # Top 5
            if sioc.ioc:
                iocs_summary.append({
                    'value': sioc.ioc.value[:30] + '...' if len(sioc.ioc.value) > 30 else sioc.ioc.value,
                    'type': sioc.ioc.ioc_type,
                    'risk': sioc.analysis.risk_level if sioc.analysis else 'N/A'
                })
        
        return {
            'id': session.id,
            'uuid': str(session.uuid),
            'title': session.title,
            'status': session.status,
            'total_iocs': session.total_iocs,
            'total_messages': session.total_messages,
            'highest_risk': session.highest_risk_level,
            'hours_active': self._calculate_session_duration(session),
            'hours_until_close': session.hours_until_auto_close,
            'top_iocs': iocs_summary,
            'last_activity': session.last_activity_at.isoformat() if session.last_activity_at else None
        }


# Instancia global (singleton)
session_manager = SessionManager()
