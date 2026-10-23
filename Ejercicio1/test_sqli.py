"""
Pruebas unitarias para el ejercicio 1.
Estas pruebas validan la mitigación del SQL Injection en buscar_funciones().

Diseño:
- El test es igual para las dos ramas.
- En la rama main la consulta se arma con f-string (LIKE '%{query}%'), con eso la inyeccion se ejecuta como SQL y las pruebas fallan.
- En la rama practico-2 el valor va por un placeholder ? (dato) + whitelist en el ORDER BY y con eso la inyeccion se trata como texto literal -> los tests PASAN.

Estas pruebas no requieren un ambiente previo, se arma una base SQLite temporal en cada test.
"""
import sqlite3
import pytest

import app as ej1


@pytest.fixture
def db_aislada(tmp_path):
    """Con esta función creo una base SQLite temporal con datos minimos para el test y apunto la app a esta db."""
    db_file = tmp_path / "test_cine.db"
    conn = sqlite3.connect(db_file)
    conn.executescript(
        """
        CREATE TABLE peliculas (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            genero TEXT,
            director TEXT
        );
        CREATE TABLE funciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pelicula_id INTEGER NOT NULL,
            fecha_hora TEXT NOT NULL,
            asientos_totales INTEGER DEFAULT 100,
            asientos_ocupados INTEGER DEFAULT 0
        );
        """
    )
    conn.execute(
        "INSERT INTO peliculas (nombre, genero, director) VALUES ('Dune', 'SciFi', 'Villeneuve')"
    )
    conn.execute(
        "INSERT INTO funciones (pelicula_id, fecha_hora, asientos_totales, asientos_ocupados) "
        "VALUES (1, '2026-07-13 14:30:00', 120, 85)"
    )
    conn.commit()
    conn.close()

    ej1.app.config["DATABASE"] = str(db_file)
    with ej1.app.app_context():
        yield


def test_inyeccion_union(db_aislada):
    """
    El UNION inyectado intenta traer datos de la db (el catálogo interno
    con los nombres y las tablas). En la versión mitigada el texto se trata como
    literal y no matchea ninguna pelicula, devolviendo 0 filas.
    """
    payload = "' UNION SELECT name, sql, 1 FROM sqlite_master -- "
    resultados = ej1.buscar_funciones(payload)
    assert len(resultados) == 0, (
        "La inyección con UNION devolvió filas, osea que la entrada se ejecutó como SQL (vulnerable)."
    )


def test_inyeccion_or(db_aislada):
    """
    Un OR '1'='1' (o un comando del estilo) se usa para romper el filtro del WHERE y devolver todas
    las filas. En la versión mitigada es texto literal, devolviendo 0 filas.
    """
    payload = "' OR '1'='1"
    resultados = ej1.buscar_funciones(payload)
    assert len(resultados) == 0, (
        "El comando OR '1'='1' devolvió filas, osea que el filtro fue evadido (vulnerable)."
    )
