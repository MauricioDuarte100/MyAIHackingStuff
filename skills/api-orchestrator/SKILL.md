# Api Orchestrator

Especialista en api-orchestrator

## Instructions
Eres un experto de élite en api-orchestrator. Tu objetivo es ejecutar la siguiente metodología con precisión quirúrgica y eficiencia técnica.

---
name: api-orchestrator
description: Sub-orquestador especializado en testing exhaustivo de APIs. Usar para: (1) Descubrir APIs REST/GraphQL/WebSocket, (2) Testing de autenticación y autorización en APIs, (3) BOLA/IDOR en endpoints, (4) GraphQL introspection y ataques, (5) Testing de mobile APIs. Trigger: cuando se necesite auditoría completa de APIs.
---

# 🔌 API Orchestrator - Orquestador de APIs

## Objetivo
Coordinar testing exhaustivo de todas las APIs identificadas en el target.

## Tipos de API a Testear

```yaml
REST API:
  - Public endpoints
  - Authenticated endpoints
  - Admin endpoints
  - Internal/Hidden endpoints

GraphQL:
  - Query operations
  - Mutation operations
  - Subscription operations
  - Introspection

WebSocket:
  - Real-time messaging
  - Event handlers
  - Authentication flow

Mobile API:
  - iOS endpoints
  - Android endpoints
  - Common mobile endpoints
```

## Plan de Testing de APIs

### Fase 1: Descubrimiento de APIs
```python
api_discovery = {
    "tasks": [
        {
            "name": "REST API Discovery",
            "methods": [
                "crawl_for_endpoints",
                "analyze_javascript",
                "check_common_paths",
                "swagger_openapi_discovery"
            ],
            "wordlists": [
                "api_endpoints.txt",
                "rest_common.txt"
            ]
        },
        {
            "name": "GraphQL Discovery",
            "methods": [
                "check_graphql_endpoints",
                "introspection_query",
                "schema_extraction"
            ],
            "endpoints": [
                "/graphql",
                "/api/graphql",
                "/v1/graphql",
                "/query",
                "/gql"
            ]
        },
        {
            "name": "WebSocket Discovery",
            "methods": [
                "check_ws_endpoints",
                "analyze_js_for_ws"
            ],
            "protocols": ["ws://", "wss://"]
        }
    ]
}
```

### Fase 2: Testing REST API
```python
rest_testing = {
    "authentication": {
        "tests": [
            {
                "name": "Auth Bypass",
                "method": "test_auth_bypass",
                "techniques": [
                    "remove_auth_header",
                    "modify_auth_token",
                    "use_expired_token",
                    "jwt_none_algorithm"
                ]
            },
            {
                "name": "Broken Authentication",
                "method": "test_broken_auth",
                "checks": ["weak_tokens", "predictable_tokens"]
            }
        ]
    },

    "authorization": {
        "tests": [
            {
                "name": "BOLA (IDOR)",
                "method": "test_bola",
                "id_params": ["id", "userId", "bookingId", "orderId"]
            },
            {
                "name": "BFLA",
                "method": "test_bfla",
                "admin_functions": ["delete", "modify", "admin"]
            },
            {
                "name": "Object Level Authorization",
                "method": "test_object_auth"
            }
        ]
    },

    "injection": {
        "tests": [
            {"name": "SQL Injection", "agent": "injection-agent"},
            {"name": "NoSQL Injection", "agent": "injection-agent"},
            {"name": "Command Injection", "agent": "injection-agent"}
        ]
    },

    "data_exposure": {
        "tests": [
            {
                "name": "Excessive Data Exposure",
                "method": "check_data_exposure",
                "sensitive_fields": ["password", "token", "secret", "key"]
            },
            {
                "name": "Mass Assignment",
                "method": "test_mass_assignment",
                "protected_fields": ["role", "admin", "balance", "verified"]
            }
        ]
    },

    "rate_limiting": {
        "tests": [
            {
                "name": "Rate Limit Check",
                "method": "test_rate_limits",
                "endpoints": ["login", "register", "password-reset"]
            },
            {
                "name": "Rate Limit Bypass",
                "method": "test_rate_limit_bypass",
                "techniques": ["ip_rotation", "header_manipulation"]
            }
        ]
    }
}
```

### Fase 3: Testing GraphQL
```python
graphql_testing = {
    "introspection": {
        "tests": [
            {
                "name": "Full Introspection",
                "method": "run_introspection",
                "output": "05-api-testing/graphql/introspection/"
            },
            {
                "name": "Schema Analysis",
                "method": "analyze_schema",
                "checks": ["sensitive_types", "deprecated_fields"]
            }
        ]
    },

    "query_attacks": {
        "tests": [
            {
                "name": "Nested Query DoS",
                "method": "test_nested_queries",
                "max_depth": 10
            },
            {
                "name": "Batch Query Attack",
                "method": "test_batch_queries",
                "batch_size": 100
            },
            {
                "name": "Alias DoS",
                "method": "test_alias_dos"
            },
            {
                "name": "Field Duplication",
                "method": "test_field_duplication"
            }
        ]
    },

    "injection": {
        "tests": [
            {
                "name": "GraphQL Injection",
                "method": "test_graphql_injection",
                "inputs": ["variables", "arguments"]
            },
            {
                "name": "SQL via GraphQL",
                "method": "test_sql_via_graphql"
            }
        ]
    },

    "authorization": {
        "tests": [
            {
                "name": "Query Authorization",
                "method": "test_query_auth",
                "check_types": ["User", "Admin", "Private"]
            },
            {
                "name": "Mutation Authorization",
                "method": "test_mutation_auth"
            },
            {
                "name": "Field Level Authorization",
                "method": "test_field_auth"
            }
        ]
    },

    "information_disclosure": {
        "tests": [
            {
                "name": "Error Message Disclosure",
                "method": "check_error_disclosure"
            },
            {
                "name": "Field Suggestion",
                "method": "test_field_suggestions"
            },
            {
                "name": "Debug Mode",
                "method": "check_debug_mode"
            }
        ]
    }
}
```

### Fase 4: Testing WebSocket
```python
websocket_testing = {
    "connection": {
        "tests": [
            {
                "name": "Origin Validation",
                "method": "test_origin_check"
            },
            {
                "name": "CSWSH",
                "method": "test_cross_site_ws_hijacking"
            },
            {
                "name": "Authentication Check",
                "method": "test_ws_auth"
            }
        ]
    },

    "messaging": {
        "tests": [
            {
                "name": "Message Injection",
                "method": "test_message_injection"
            },
            {
                "name": "Message Manipulation",
                "method": "test_message_manipulation"
            },
            {
                "name": "Unauthorized Actions",
                "method": "test_ws_unauthorized_actions"
            }
        ]
    },

    "dos": {
        "tests": [
            {
                "name": "Connection Flood",
                "method": "test_connection_limit",
                "max_connections": 100
            },
            {
                "name": "Message Flood",
                "method": "test_message_limit"
            }
        ]
    }
}
```

### Fase 5: Testing Mobile API
```python
mobile_api_testing = {
    "discovery": {
        "methods": [
            "decompile_apk",
            "analyze_ipa",
            "intercept_traffic"
        ],
        "endpoints_to_find": [
            "/api/mobile/",
            "/m/api/",
            "/app/api/"
        ]
    },

    "specific_tests": [
        {
            "name": "Certificate Pinning Bypass",
            "method": "test_cert_pinning"
        },
        {
            "name": "API Key Exposure",
            "method": "find_hardcoded_keys"
        },
        {
            "name": "Insecure Data Storage",
            "method": "check_data_storage"
        }
    ]
}
```

## Ejecución del Orquestador

```python
class APIOrchestrator:
    def __init__(self):
        self.api_agent = get_agent("api-agent")
        self.injection_agent = get_agent("injection-agent")
        self.auth_agent = get_agent("auth-agent")

        self.discovered_apis = {
            "rest": [],
            "graphql": [],
            "websocket": [],
            "mobile": []
        }

        self.findings = []

    def run(self):
        """Ejecutar testing completo de APIs"""

        # Fase 1: Descubrimiento
        print("[*] Phase 1: API Discovery")
        self.discover_apis()

        # Fase 2: REST Testing
        if self.discovered_apis["rest"]:
            print("[*] Phase 2: REST API Testing")
            self.test_rest_apis()

        # Fase 3: GraphQL Testing
        if self.discovered_apis["graphql"]:
            print("[*] Phase 3: GraphQL Testing")
            self.test_graphql()

        # Fase 4: WebSocket Testing
        if self.discovered_apis["websocket"]:
            print("[*] Phase 4: WebSocket Testing")
            self.test_websockets()

        # Fase 5: Mobile API Testing
        print("[*] Phase 5: Mobile API Testing")
        self.test_mobile_api()

        return self.findings

    def discover_apis(self):
        """Descubrir todas las APIs"""
        # REST
        rest_endpoints = self.api_agent.discover_rest_endpoints()
        self.discovered_apis["rest"] = rest_endpoints

        # GraphQL
        graphql_endpoints = self.api_agent.discover_graphql()
        self.discovered_apis["graphql"] = graphql_endpoints

        # WebSocket
        ws_endpoints = self.api_agent.discover_websockets()
        self.discovered_apis["websocket"] = ws_endpoints

        # Guardar descubrimientos
        self.save_discovery_results()

    def test_rest_apis(self):
        """Testing de APIs REST"""
        for endpoint in self.discovered_apis["rest"]:
            # Authentication tests
            auth_results = self.auth_agent.test_endpoint_auth(endpoint)

            # Authorization tests (IDOR, BOLA)
            authz_results = self.auth_agent.test_authorization(endpoint)

            # Injection tests
            injection_results = self.injection_agent.test_endpoint(endpoint)

            # Data exposure
            exposure_results = self.api_agent.check_data_exposure(endpoint)

            # Consolidar hallazgos
            self.consolidate_findings([
                auth_results, authz_results,
                injection_results, exposure_results
            ])

    def test_graphql(self):
        """Testing de GraphQL"""
        for endpoint in self.discovered_apis["graphql"]:
            # Introspección
            schema = self.api_agent.graphql_introspection(endpoint)

            if schema:
                # Analizar schema
                sensitive_fields = self.api_agent.analyze_graphql_schema(schema)

                # Query attacks
                query_results = self.api_agent.test_graphql_queries(endpoint, schema)

                # Authorization
                auth_results = self.api_agent.test_graphql_auth(endpoint, schema)

                # Injection via GraphQL
                injection_results = self.injection_agent.test_graphql_injection(
                    endpoint, schema
                )

                self.consolidate_findings([
                    query_results, auth_results, injection_results
                ])

    def test_websockets(self):
        """Testing de WebSockets"""
        for endpoint in self.discovered_apis["websocket"]:
            # Connection security
            conn_results = self.api_agent.test_ws_connection(endpoint)

            # Message security
            msg_results = self.api_agent.test_ws_messages(endpoint)

            self.consolidate_findings([conn_results, msg_results])

    def test_mobile_api(self):
        """Testing de APIs móviles"""
        # Buscar endpoints específicos de móvil
        mobile_endpoints = self.api_agent.discover_mobile_endpoints()

        for endpoint in mobile_endpoints:
            results = self.api_agent.test_mobile_endpoint(endpoint)
            self.consolidate_findings([results])

    def consolidate_findings(self, results_list):
        """Consolidar hallazgos de múltiples tests"""
        for results in results_list:
            if results and results.get("findings"):
                for finding in results["findings"]:
                    self.findings.append(finding)
                    documentation_agent.log_finding(finding)

    def get_api_coverage_report(self):
        """Generar reporte de cobertura de APIs"""
        return {
            "rest": {
                "discovered": len(self.discovered_apis["rest"]),
                "tested": len([e for e in self.discovered_apis["rest"] if e.get("tested")])
            },
            "graphql": {
                "discovered": len(self.discovered_apis["graphql"]),
                "introspected": len([e for e in self.discovered_apis["graphql"] if e.get("schema")])
            },
            "websocket": {
                "discovered": len(self.discovered_apis["websocket"]),
                "tested": len([e for e in self.discovered_apis["websocket"] if e.get("tested")])
            },
            "total_findings": len(self.findings)
        }
```

## Payloads Específicos para APIs

```python
api_payloads = {
    "idor_ids": [
        "1", "0", "-1", "999999",
        "00000000-0000-0000-0000-000000000001",
        "../1", "1;SELECT", "1 OR 1=1"
    ],

    "mass_assignment": {
        "role": "admin",
        "isAdmin": True,
        "admin": True,
        "balance": 999999,
        "verified": True,
        "banned": False
    },

    "rate_limit_bypass_headers": [
        "X-Forwarded-For",
        "X-Real-IP",
        "X-Originating-IP",
        "X-Remote-IP",
        "X-Client-IP"
    ],

    "graphql_dos": {
        "nested_depth": 10,
        "batch_size": 100,
        "alias_count": 1000
    }
}
```

## Output del Orquestador

```
05-api-testing/
├── rest/
│   ├── endpoints.json
│   ├── auth-bypass/
│   ├── idor/
│   ├── injection/
│   └── data-exposure/
├── graphql/
│   ├── introspection/
│   │   └── schema.json
│   ├── queries/
│   ├── mutations/
│   └── vulnerabilities/
├── websocket/
│   ├── endpoints.json
│   └── vulnerabilities/
└── mobile-api/
    ├── endpoints.json
    └── vulnerabilities/
```


## Available Resources
- . (Directorio de la skill)
