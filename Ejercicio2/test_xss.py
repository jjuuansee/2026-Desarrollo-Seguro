"""
Pruebas unitarias para el ejercicio 2.
Estas pruebas validan la mitigación del Cross-Site Scripting almacenado.

El dato peligroso es el de descripción, porque se guarda en la base y luego se muestra en
/edit/<id>. En la rama main el template usa {{ ... | safe }}, con eso el HTML se inyecta tal
cual (siendo vulnerable) y las pruebas fallan. En la rama practico-2 había sacado el | safe, y ahi si Jinja
autoescapa el valor y las pruebas pasan.

Estas pruebas no requieren un ambiente previo, se arma la base SQLite temporal y cliente de pruebas de Flask.
"""
import sqlite3
import pytest

import app as ej2


@pytest.fixture
def client(tmp_path):
    db_file = tmp_path / "test_cine2.db"
    conn = sqlite3.connect(db_file)
    conn.executescript(
        """
        CREATE TABLE peliculas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            genero TEXT NOT NULL,
            director TEXT NOT NULL,
            descripcion TEXT
        );
        """
    )
    conn.execute(
        "INSERT INTO peliculas (id, nombre, genero, director, descripcion) "
        "VALUES (1, 'Dune', 'SciFi', 'Villeneuve', 'desc original')"
    )
    conn.commit()
    conn.close()

    ej2.app.config["DATABASE"] = str(db_file)
    ej2.app.config["TESTING"] = True
    with ej2.app.test_client() as c:
        yield c


def guardar_descripcion(client, descripcion):
    """Con esta función guardo una descripción maliciosa desde POST /edit/1 (para simular un atacante)."""
    return client.post(
        "/edit/1",
        data={"nombre": "Dune", "genero": "SciFi",
              "director": "Villeneuve", "descripcion": descripcion},
    )


def test_xss_script_escaped(client):
    payload = "<script>alert('xss-practica4')</script>"
    guardar_descripcion(client, payload)

    html = client.get("/edit/1").get_data(as_text=True)
    # En la versión mitigada el payload no debería aparecer crudo en el HTML (tiene que estar escaped).
    assert payload not in html, (
        "El <script> se renderizó crudo, comprobando que hay XSS almacenado (vulnerable)."
    )
    # Acá confirmo que el valor esté (pero escaped).
    assert "&lt;script&gt;" in html


def test_xss_atributo_onerror_escaped(client):
    """
    En vez de una etiqueta <script>, pruebo un atributo de evento (onerror) dentro de un <img>. En la versión mitigada Jinja lo deja escaped igual, osea que no queda crudo.
    """
    payload = "<img src=x onerror=alert('xss-p4')>"
    guardar_descripcion(client, payload)

    html = client.get("/edit/1").get_data(as_text=True)
    # El comando no debería aparecer crudo en el HTML.
    assert payload not in html, (
        "El <img onerror> se renderizó crudo, por lo que hay XSS almacenado (vulnerable)."
    )
    # Tiene que estar el comando pero escaped (&lt;img...).
    assert "&lt;img" in html
