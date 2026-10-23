"""
Pruebas de integracion (Pytest y requests) para el ejercicio 4.
Estas pruebas validan la mitigación de Server-Side Template Injection / SpEL Injection del ejercicio 4.

El parámetro 'buscar' de la ruta / se usaba como expresión SpEL y se evaluaba, de ahí el
resultado se mostraba en el mensaje de la pagina.
- En la rama main evalúa la expresión '9999*9999' y devuelve '99980001' en la página,
  y "'p4'+'_'+'ssti'" devuelve 'p4_ssti', con esos resultados los tests fallan.
- En la rama practico-2 el valor se trata como texto literal, sin evaluar, esos
  resultados de la rama main nunca aparecen, pasando entonces los tests.

Como aclaración, el buscador re-muestra el texto ingresado tal cual en las dos ramas, por eso
en el test no se compara el literal, sino que se verifica que el resultado de evaluar la
expresión no aparezca (solo aparecería si hubo evaluación).

Se ejecuta contra la app dockerizada (BASE_URL, por defecto 8081 en practico-2 y en main el 8080).
"""
import os
import requests

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8081")
TIMEOUT = 10


def test_expresion_aritmetica():
    r = requests.get(f"{BASE_URL}/", params={"buscar": "9999*9999"}, timeout=TIMEOUT)
    assert "99980001" not in r.text, (
        "La expresión 9999*9999 se evaluó como 99980001, confirmando que hay SSTI/SpEL injection (vulnerable)."
    )


def test_concatenacion_no_se_evalua():
    r = requests.get(f"{BASE_URL}/", params={"buscar": "'p4'+'_'+'ssti'"}, timeout=TIMEOUT)
    assert "p4_ssti" not in r.text, (
        "La expresión \"'p4'+'_'+'ssti'\" se evaluó como p4_ssti, confirmando que hay SSTI/SpEL injection (vulnerable)."
    )
