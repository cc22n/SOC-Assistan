"""
SOC Agent - OpenAPI/Swagger Documentation
Sprint 4 - Auto-generated from Pydantic schemas

Genera la especificación OpenAPI 3.0 para toda la API v2.
Se sirve en /api/docs (Swagger UI) y /api/docs/openapi.json (spec raw).

Uso:
    from app.docs.openapi import docs_bp
    app.register_blueprint(docs_bp)
"""
from flask import Blueprint, jsonify, render_template_string
import logging

logger = logging.getLogger(__name__)

docs_bp = Blueprint('api_docs', __name__, url_prefix='/api/docs')


# =============================================================================
# OPENAPI 3.0 SPEC
# =============================================================================

def generate_openapi_spec():
    """Genera la especificación OpenAPI 3.0 completa"""
    return {
        "openapi": "3.0.3",
        "info": {
            "title": "SOC Agent API",
            "description": (
                "API REST para la plataforma de Threat Intelligence SOC Agent.\n\n"
                "Integra 19 APIs de threat intelligence y 4 proveedores LLM para "
                "análisis de IOCs (IPs, dominios, hashes, URLs).\n\n"
                "**Autenticación:** Todas las rutas (excepto `/health`) requieren sesión activa via cookie."
            ),
            "version": "5.0.0",
            "contact": {"name": "SOC Agent"},
            "license": {"name": "MIT"}
        },
        "servers": [
            {"url": "/api/v2", "description": "API v2 principal"},
            {"url": "/api/v2/incidents", "description": "Incidents API"}
        ],
        "tags": [
            {"name": "Analysis", "description": "Análisis de IOCs con threat intelligence + LLM"},
            {"name": "Chat", "description": "Chat interactivo con asistente SOC"},
            {"name": "Sessions", "description": "Sesiones de investigación"},
            {"name": "Incidents", "description": "Gestión de incidentes de seguridad"},
            {"name": "APIs", "description": "Estado y testing de APIs de threat intelligence"},
            {"name": "LLM", "description": "Proveedores LLM y testing"},
            {"name": "System", "description": "Health check y estado del sistema"}
        ],
        "paths": {
            # =================== ANALYSIS ===================
            "/analyze/enhanced": {
                "post": {
                    "tags": ["Analysis"],
                    "summary": "Analizar IOC",
                    "description": (
                        "Análisis completo de un IOC contra las APIs de threat intelligence configuradas. "
                        "Incluye análisis LLM, mapeo MITRE ATT&CK, y caché inteligente.\n\n"
                        "**Rate limit:** 5/min, 30/hr"
                    ),
                    "operationId": "analyzeEnhanced",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/AnalyzeRequest"},
                                "examples": {
                                    "ip": {
                                        "summary": "Analizar IP maliciosa",
                                        "value": {"ioc": "185.220.101.34", "type": "ip", "context": "Detectado en logs de firewall"}
                                    },
                                    "domain": {
                                        "summary": "Analizar dominio sospechoso",
                                        "value": {"ioc": "malware-c2.evil.com", "type": "domain"}
                                    },
                                    "hash": {
                                        "summary": "Analizar hash de malware",
                                        "value": {"ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "hash"}
                                    },
                                    "cached": {
                                        "summary": "Forzar re-análisis (ignorar caché)",
                                        "value": {"ioc": "8.8.8.8", "type": "ip", "force_refresh": True}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "Análisis completado",
                            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/AnalyzeResponse"}}}
                        },
                        "400": {"description": "IOC inválido o tipo no detectado", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ErrorResponse"}}}},
                        "422": {"description": "Error de validación Pydantic", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ValidationError"}}}},
                        "429": {"description": "Rate limit excedido"}
                    }
                }
            },

            # =================== CHAT ===================
            "/chat/message": {
                "post": {
                    "tags": ["Chat"],
                    "summary": "Enviar mensaje al chat SOC",
                    "description": (
                        "Chat interactivo con el asistente SOC. Soporta sesiones de investigación, "
                        "detección automática de IOCs en el mensaje, y selección de proveedor LLM.\n\n"
                        "**Rate limit:** 10/min, 60/hr"
                    ),
                    "operationId": "chatMessage",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/ChatMessageRequest"},
                                "examples": {
                                    "simple": {
                                        "summary": "Pregunta simple",
                                        "value": {"message": "¿Qué técnicas MITRE usa APT29?"}
                                    },
                                    "with_session": {
                                        "summary": "Mensaje en sesión de investigación",
                                        "value": {"message": "Analiza esta IP: 185.220.101.34", "session_id": 5, "llm_provider": "groq"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": {"description": "Respuesta del asistente", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ChatMessageResponse"}}}},
                        "422": {"description": "Error de validación"},
                        "429": {"description": "Rate limit excedido"}
                    }
                }
            },

            # =================== SESSIONS ===================
            "/sessions": {
                "get": {
                    "tags": ["Sessions"],
                    "summary": "Listar sesiones del usuario",
                    "operationId": "listSessions",
                    "parameters": [
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 20}},
                        {"name": "status", "in": "query", "schema": {"type": "string", "enum": ["active", "closed"]}}
                    ],
                    "responses": {"200": {"description": "Lista de sesiones"}}
                },
                "post": {
                    "tags": ["Sessions"],
                    "summary": "Crear nueva sesión de investigación",
                    "operationId": "createSession",
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string", "maxLength": 200},
                                        "close_existing": {"type": "boolean", "default": False}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Sesión creada"}}
                }
            },
            "/sessions/active": {
                "get": {
                    "tags": ["Sessions"],
                    "summary": "Obtener sesión activa del usuario",
                    "operationId": "getActiveSession",
                    "responses": {"200": {"description": "Sesión activa o null"}}
                }
            },
            "/sessions/{session_id}": {
                "get": {
                    "tags": ["Sessions"],
                    "summary": "Detalle de sesión",
                    "operationId": "getSession",
                    "parameters": [{"name": "session_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "Detalle de sesión"}, "404": {"description": "Sesión no encontrada"}, "403": {"description": "No autorizado"}}
                },
                "put": {
                    "tags": ["Sessions"],
                    "summary": "Actualizar sesión",
                    "operationId": "updateSession",
                    "parameters": [{"name": "session_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "description": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Sesión actualizada"}}
                }
            },
            "/sessions/{session_id}/close": {
                "post": {
                    "tags": ["Sessions"],
                    "summary": "Cerrar sesión de investigación",
                    "operationId": "closeSession",
                    "parameters": [{"name": "session_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "Sesión cerrada"}}
                }
            },
            "/sessions/{session_id}/messages": {
                "get": {
                    "tags": ["Sessions"],
                    "summary": "Mensajes de la sesión",
                    "operationId": "getSessionMessages",
                    "parameters": [
                        {"name": "session_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}}
                    ],
                    "responses": {"200": {"description": "Lista de mensajes"}}
                }
            },
            "/sessions/{session_id}/iocs": {
                "get": {
                    "tags": ["Sessions"],
                    "summary": "IOCs de la sesión",
                    "operationId": "getSessionIOCs",
                    "parameters": [{"name": "session_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "Lista de IOCs vinculados"}}
                }
            },
            "/sessions/{session_id}/export": {
                "get": {
                    "tags": ["Sessions"],
                    "summary": "Exportar sesión",
                    "description": "Exporta una sesión completa en JSON, Markdown, PDF o DOCX.",
                    "operationId": "exportSession",
                    "parameters": [
                        {"name": "session_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        {"name": "format", "in": "query", "schema": {"type": "string", "enum": ["json", "markdown", "pdf", "docx"], "default": "json"}}
                    ],
                    "responses": {
                        "200": {"description": "Sesión exportada (formato varía según parámetro)"}
                    }
                }
            },

            # =================== INCIDENTS ===================
            "/incidents": {
                "post": {
                    "tags": ["Incidents"],
                    "summary": "Crear incidente",
                    "operationId": "createIncident",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/IncidentCreateRequest"},
                                "examples": {
                                    "basic": {
                                        "summary": "Incidente básico",
                                        "value": {"title": "C2 detectado en red interna", "severity": "P1", "description": "IP 185.220.101.34 comunicándose con servidor C2 conocido"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"201": {"description": "Incidente creado"}}
                },
                "get": {
                    "tags": ["Incidents"],
                    "summary": "Listar incidentes",
                    "operationId": "listIncidents",
                    "parameters": [
                        {"name": "status", "in": "query", "description": "CSV: open,investigating", "schema": {"type": "string"}},
                        {"name": "severity", "in": "query", "schema": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]}},
                        {"name": "assigned_to", "in": "query", "schema": {"type": "integer"}},
                        {"name": "my_only", "in": "query", "schema": {"type": "boolean", "default": False}},
                        {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50}}
                    ],
                    "responses": {"200": {"description": "Lista de incidentes"}}
                }
            },
            "/incidents/{incident_id}": {
                "get": {
                    "tags": ["Incidents"],
                    "summary": "Detalle de incidente",
                    "operationId": "getIncident",
                    "parameters": [{"name": "incident_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "Detalle con IOCs"}, "403": {"description": "No autorizado"}, "404": {"description": "No encontrado"}}
                },
                "put": {
                    "tags": ["Incidents"],
                    "summary": "Actualizar incidente",
                    "operationId": "updateIncident",
                    "parameters": [{"name": "incident_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "title": {"type": "string"},
                                        "description": {"type": "string"},
                                        "severity": {"type": "string", "enum": ["P1", "P2", "P3", "P4"]},
                                        "assigned_to": {"type": "integer"},
                                        "notes": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Incidente actualizado"}, "403": {"description": "No autorizado"}}
                }
            },
            "/incidents/{incident_id}/status": {
                "put": {
                    "tags": ["Incidents"],
                    "summary": "Cambiar estado de incidente",
                    "operationId": "changeIncidentStatus",
                    "parameters": [{"name": "incident_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["status"],
                                    "properties": {
                                        "status": {"type": "string", "enum": ["open", "investigating", "resolved", "closed"]},
                                        "reason": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Estado actualizado"}, "403": {"description": "No autorizado"}}
                }
            },
            "/incidents/{incident_id}/notes": {
                "post": {
                    "tags": ["Incidents"],
                    "summary": "Agregar nota al timeline",
                    "operationId": "addIncidentNote",
                    "parameters": [{"name": "incident_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["content"],
                                    "properties": {
                                        "content": {"type": "string"},
                                        "type": {"type": "string", "enum": ["note", "finding", "action"], "default": "note"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Nota agregada"}}
                }
            },
            "/incidents/{incident_id}/iocs": {
                "post": {
                    "tags": ["Incidents"],
                    "summary": "Vincular IOCs a incidente",
                    "operationId": "linkIOCs",
                    "parameters": [{"name": "incident_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["ioc_ids"],
                                    "properties": {
                                        "ioc_ids": {"type": "array", "items": {"type": "integer"}},
                                        "role": {"type": "string", "enum": ["primary", "related", "context"], "default": "related"},
                                        "notes": {"type": "string"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "IOCs vinculados"}}
                }
            },
            "/incidents/{incident_id}/iocs/{ioc_id}": {
                "delete": {
                    "tags": ["Incidents"],
                    "summary": "Desvincular IOC",
                    "operationId": "unlinkIOC",
                    "parameters": [
                        {"name": "incident_id", "in": "path", "required": True, "schema": {"type": "integer"}},
                        {"name": "ioc_id", "in": "path", "required": True, "schema": {"type": "integer"}}
                    ],
                    "responses": {"200": {"description": "IOC desvinculado"}, "404": {"description": "Vínculo no encontrado"}}
                }
            },
            "/incidents/{incident_id}/timeline": {
                "get": {
                    "tags": ["Incidents"],
                    "summary": "Timeline completo del incidente",
                    "description": "Incluye notas propias + mensajes del chat si hay sesión vinculada.",
                    "operationId": "getIncidentTimeline",
                    "parameters": [{"name": "incident_id", "in": "path", "required": True, "schema": {"type": "integer"}}],
                    "responses": {"200": {"description": "Timeline ordenado cronológicamente"}}
                }
            },
            "/incidents/stats": {
                "get": {
                    "tags": ["Incidents"],
                    "summary": "Estadísticas de incidentes",
                    "operationId": "getIncidentStats",
                    "responses": {"200": {"description": "Conteos por estado y severidad"}}
                }
            },

            # =================== APIs STATUS ===================
            "/apis/status": {
                "get": {
                    "tags": ["APIs"],
                    "summary": "Estado de todas las APIs de threat intelligence",
                    "description": "Retorna uso diario, health, y configuración de las 18 APIs.",
                    "operationId": "apisStatus",
                    "responses": {"200": {"description": "Estado de APIs"}}
                }
            },
            "/apis/{api_name}/test": {
                "post": {
                    "tags": ["APIs"],
                    "summary": "Probar una API específica",
                    "operationId": "testApi",
                    "parameters": [{"name": "api_name", "in": "path", "required": True, "schema": {"type": "string"}}],
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "test_ioc": {"type": "string", "default": "8.8.8.8"}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Resultado del test"}}
                }
            },

            # =================== LLM ===================
            "/llm/providers": {
                "get": {
                    "tags": ["LLM"],
                    "summary": "Proveedores LLM disponibles",
                    "operationId": "llmProviders",
                    "responses": {"200": {"description": "Lista de proveedores con disponibilidad y modelos"}}
                }
            },
            "/llm/test": {
                "post": {
                    "tags": ["LLM"],
                    "summary": "Probar proveedor LLM",
                    "operationId": "testLlm",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["provider"],
                                    "properties": {
                                        "provider": {"type": "string", "enum": ["xai", "openai", "groq", "gemini"]}
                                    }
                                }
                            }
                        }
                    },
                    "responses": {"200": {"description": "Resultado del test con tiempo de respuesta"}}
                }
            },

            # =================== SYSTEM ===================
            "/health": {
                "get": {
                    "tags": ["System"],
                    "summary": "Health check",
                    "description": "Verifica estado de BD y APIs configuradas. No requiere autenticación.",
                    "operationId": "healthCheck",
                    "security": [],
                    "responses": {"200": {"description": "Estado del sistema"}}
                }
            }
        },

        "components": {
            "schemas": {
                "AnalyzeRequest": {
                    "type": "object",
                    "required": ["ioc"],
                    "properties": {
                        "ioc": {"type": "string", "minLength": 1, "maxLength": 2048, "description": "IOC value (IP, domain, hash, URL)"},
                        "type": {"type": "string", "enum": ["ip", "domain", "hash", "url"], "description": "IOC type (auto-detected if omitted)"},
                        "context": {"type": "string", "maxLength": 5000, "default": "", "description": "User context for LLM analysis"},
                        "use_llm_planning": {"type": "boolean", "default": True, "description": "Enable LLM-guided API selection"},
                        "session_id": {"type": "integer", "minimum": 1, "description": "Investigation session ID"},
                        "force_refresh": {"type": "boolean", "default": False, "description": "Bypass cache"}
                    }
                },
                "AnalyzeResponse": {
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean"},
                        "analysis_id": {"type": "integer"},
                        "ioc": {"type": "string"},
                        "type": {"type": "string"},
                        "confidence_score": {"type": "integer", "minimum": 0, "maximum": 100},
                        "risk_level": {"type": "string", "enum": ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "LIMPIO"]},
                        "llm_analysis": {"type": "object", "nullable": True},
                        "sources_used": {"type": "array", "items": {"type": "string"}},
                        "api_results": {"type": "object", "description": "Raw results from each API"},
                        "mitre_techniques": {"type": "array", "items": {"type": "object"}},
                        "processing_time": {"type": "number"},
                        "cached": {"type": "boolean"},
                        "cache_age_minutes": {"type": "integer", "nullable": True},
                        "session_id": {"type": "integer", "nullable": True},
                        "timestamp": {"type": "string", "format": "date-time"}
                    }
                },
                "ChatMessageRequest": {
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": {"type": "string", "minLength": 1, "maxLength": 10000},
                        "session_id": {"type": "integer", "minimum": 1},
                        "llm_provider": {"type": "string", "enum": ["xai", "openai", "groq", "gemini"]},
                        "history": {"type": "array", "items": {"type": "object"}, "maxItems": 50}
                    }
                },
                "ChatMessageResponse": {
                    "type": "object",
                    "properties": {
                        "success": {"type": "boolean"},
                        "response": {"type": "string"},
                        "requires_analysis": {"type": "boolean"},
                        "analysis_data": {"type": "object", "nullable": True},
                        "session_id": {"type": "integer", "nullable": True},
                        "llm_provider": {"type": "string"},
                        "timestamp": {"type": "string", "format": "date-time"}
                    }
                },
                "IncidentCreateRequest": {
                    "type": "object",
                    "required": ["title"],
                    "properties": {
                        "title": {"type": "string", "minLength": 1, "maxLength": 200},
                        "description": {"type": "string"},
                        "severity": {"type": "string", "enum": ["P1", "P2", "P3", "P4"], "default": "P3"},
                        "assigned_to": {"type": "integer", "description": "User ID"},
                        "session_id": {"type": "integer"},
                        "analysis_id": {"type": "integer"},
                        "ioc_ids": {"type": "array", "items": {"type": "integer"}},
                        "primary_ioc_id": {"type": "integer"}
                    }
                },
                "ErrorResponse": {
                    "type": "object",
                    "properties": {
                        "error": {"type": "string"},
                        "details": {"type": "object", "nullable": True}
                    }
                },
                "ValidationError": {
                    "type": "object",
                    "properties": {
                        "error": {"type": "string", "example": "Validation error"},
                        "details": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "field": {"type": "string"},
                                    "message": {"type": "string"},
                                    "type": {"type": "string"}
                                }
                            }
                        },
                        "status_code": {"type": "integer", "example": 422}
                    }
                }
            },
            "securitySchemes": {
                "sessionCookie": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "session",
                    "description": "Flask session cookie (login via /auth/login)"
                }
            }
        },
        "security": [{"sessionCookie": []}]
    }


# =============================================================================
# ROUTES
# =============================================================================

@docs_bp.route('/openapi.json')
def openapi_spec():
    """Retorna la especificación OpenAPI como JSON"""
    return jsonify(generate_openapi_spec())


@docs_bp.route('')
@docs_bp.route('/')
def swagger_ui():
    """Swagger UI embebida"""
    return render_template_string(SWAGGER_HTML)


# =============================================================================
# SWAGGER UI HTML (CDN - sin dependencias locales)
# =============================================================================

SWAGGER_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Agent - API Documentation</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <style>
        body { margin: 0; padding: 0; background: #1a1a2e; }
        .swagger-ui .topbar { display: none; }
        .swagger-ui { max-width: 1200px; margin: 0 auto; }
        .header-banner {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 40px;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        }
        .header-banner h1 { margin: 0 0 5px 0; font-size: 24px; }
        .header-banner p { margin: 0; opacity: 0.85; font-size: 14px; }
        .header-banner .badges { margin-top: 10px; }
        .header-banner .badge {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 12px;
            margin-right: 8px;
        }
    </style>
</head>
<body>
    <div class="header-banner">
        <h1>SOC Agent API</h1>
        <p>Threat Intelligence Platform - API Documentation</p>
        <div class="badges">
            <span class="badge">v5.0</span>
            <span class="badge">19 APIs</span>
            <span class="badge">4 LLM Providers</span>
            <span class="badge">OpenAPI 3.0</span>
        </div>
    </div>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({
            url: '/api/docs/openapi.json',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIBundle.SwaggerUIStandalonePreset
            ],
            layout: "BaseLayout",
            defaultModelsExpandDepth: 1,
            defaultModelExpandDepth: 2,
            docExpansion: "list",
            filter: true,
            tryItOutEnabled: true
        });
    </script>
</body>
</html>
"""
