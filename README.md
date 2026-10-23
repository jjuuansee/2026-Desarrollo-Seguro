# Práctica 4: Pruebas de seguridad

Cada ejercicio tiene sus pruebas automáticas para verificar la presencia de las vulnerabilidades mitigadas en la Práctica 2.

Las mismas pruebas corren en las dos ramas del repositorio:

- En `main` (código original, osea el vulnerable) las pruebas fallan.
- En `practico-2` (código mitigado) si pasan las pruebas.

## Archivos de pruebas

| Ejercicio | Vulnerabilidad | Tipo | Herramienta | Archivo |
|----|----------------|------|-------------|---------|
| 1 | SQL Injection (CWE-89) | Unitaria | Pytest | `Ejercicio1/test_sqli.py` |
| 2 | Stored XSS (CWE-79) | Unitaria | Pytest | `Ejercicio2/test_xss.py` |
| 3 | Unrestricted File Upload (CWE-434) | Integración | Pytest y requests | `Ejercicio3/test_upload.py` |
| 4 | SSTI / SpEL Injection (CWE-917) | Integración | Pytest y requests | `Ejercicio4/test_ssti.py` |
| 5 | Almacenamiento inseguro (CWE-257/327) | Unitaria | JUnit 5 y Mockito | `Ejercicio5/src/test/java/com/cinebuscador/AlmacenamientoInseguroTest.java` |

## Pruebas unitarias (no requieren ambiente)

Solo necesitan Python (para el ejercicio 1 y 2) o Maven (para el ejercicio 5). No hace falta levantar docker.

### Ejercicio 1 - SQL Injection (Pytest)

```bash
cd Ejercicio1
pip install -r requirements.txt pytest
pytest -v
```

### Ejercicio 2 - XSS (Pytest)

```bash
cd Ejercicio2
pip install -r requirements.txt pytest
pytest -v
```

### Ejercicio 5 - Almacenamiento inseguro (JUnit)

```bash
cd Ejercicio5
mvn test
```

## Pruebas de integración (en el ambiente con docker)

Estas pruebas si que requieren la app corriendo en docker, y Python con `pytest` + `requests`:

```bash
pip install pytest requests
```

### Ejercicio 3 - File Upload

```bash
cd Ejercicio3
docker compose up --build -d     # levanta la app (en practico-2 en el puerto 8081)
pytest -v                         # usa BASE_URL = http://localhost:8081 por defecto
docker compose down
```

### Ejercicio 4 - SSTI

```bash
cd Ejercicio4
docker compose up --build -d
pytest -v
docker compose down
```

> **Nota por el tema del puerto:** en la rama `main` el `docker-compose.yml` usa el
> puerto **8080**; en `practico-2` usa el **8081** (el valor por defecto del
> test). Para correr los tests de integración en `main`, hay que indicar la URL:
>
> ```bash
> BASE_URL=http://localhost:8080 pytest -v
> ```