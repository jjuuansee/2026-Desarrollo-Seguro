"""
Pruebas de integración (Pytest y requests) para el ejercicio 3.
Estas pruebas validan la mitigación de Unrestricted File Upload del Ejercicio 3.

Las pruebas se ejecutan contra la app dockerizada corriendo. La URL base se toma de la variable de entorno BASE_URL (por defecto http://localhost:8081, el puerto del docker-compose
de practico-2, mientras que en main el contenedor publica el 8080).

La idea de las pruebas es que un atacante intenta subir archivos que no son imagenes (un .html con un script,
o un .png falso con un contenido que no es de una imagen). Si la mitigación funciona, esos
archivos son rechazados y no quedan en /uploads/...
- En la rama main (donde se guarda cualquier archivo con su nombre original) esos archivos quedan guardados y
  accesibles, fallando los tests.
- En la rama practico-2 (hay una whitelist de extensiones, validación de contenido con ImageIO y
  renombrado UUID) esos archivos son rechazados, pasando los tests.
"""
import os
import uuid
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8081")
PELICULA_ID = 1
TIMEOUT = 10


def subir(nombre, contenido, content_type):
    archivos = {"afiche": (nombre, contenido, content_type)}
    return requests.post(
        f"{BASE_URL}/upload/{PELICULA_ID}", files=archivos, timeout=TIMEOUT
    )


def test_no_se_puede_subir_html_ejecutable():
    """Un .html con un <script> no tiene que quedar guardado ni accesible."""
    nombre = f"evil_{uuid.uuid4().hex}.html"
    subir(nombre, "<script>alert('p4-upload')</script>", "text/html")

    r = requests.get(f"{BASE_URL}/uploads/{nombre}", timeout=TIMEOUT)
    assert r.status_code == 404, (
        f"El archivo {nombre} quedó accesible (HTTP {r.status_code}), se aceptó un "
        "archivo que no es una imagen (habiendo file upload sin restricción, vulnerable)."
    )


def test_no_se_puede_subir_png_falso():
    """Un .png con contenido que no es de una imagen real tiene que ser rechazado."""
    nombre = f"evil_{uuid.uuid4().hex}.png"
    subir(nombre, "<script>alert('p4-upload')</script>", "image/png")

    r = requests.get(f"{BASE_URL}/uploads/{nombre}", timeout=TIMEOUT)
    assert r.status_code == 404, (
        f"El .png falso {nombre} quedó accesible (HTTP {r.status_code}), no se validó "
        "el contenido real del archivo (vulnerable)."
    )
