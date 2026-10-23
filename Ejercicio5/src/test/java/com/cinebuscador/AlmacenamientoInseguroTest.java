package com.cinebuscador;

import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.ui.ConcurrentModel;

import com.cinebuscador.controller.AuthController;
import com.cinebuscador.model.User;
import com.cinebuscador.repository.UserRepository;

/**
 * Pruebas unitarias (JUnit 5 y Mockito) para el ejercicio 5
 * Estas pruebas validan la mitigacion de Almacenamiento Inseguro de
 * contraseñas.
 *
 * No levanto Spring ni ninguna base de datos, se hace el mock de
 * UserRepository, se registra un
 * usuario y se captura lo que el controller intenta guardar.
 *
 * - En la rama main la contraseña se "cifra" con AES/ECB y clave fija (que es
 * reversible y determinístico), por lo que el valor guardado no es un hash
 * bcrypt y dos claves iguales
 * dan el mismo valor, con eso los tests fallan.
 * - En la rama practico-2 se usa bcrypt (one-way y salt), el valor empieza con
 * "$2" y
 * dos claves iguales dan hashes distintos por el salt, con esto si se pasan los
 * tests.
 *
 * El test referencia solo las clases comunes a las dos ramas (AuthController,
 * UserRepository y User), por eso compila y corre en las dos.
 */
class AlmacenamientoInseguroTest {

    /** Registro un usuario y devuelvo la contraseña como se intento guardar. */
    private String registrarYObtenerContrasenaGuardada(String username, String password) {
        UserRepository repo = mock(UserRepository.class);
        when(repo.findByUsername(anyString())).thenReturn(Optional.empty());

        AuthController controller = new AuthController(repo);
        controller.register(username, password, password, new ConcurrentModel());

        ArgumentCaptor<User> captor = ArgumentCaptor.forClass(User.class);
        verify(repo).save(captor.capture());
        return captor.getValue().getPassword();
    }

    @Test
    void password_guardada_como_hash_bcrypt_o_no() {
        String almacenada = registrarYObtenerContrasenaGuardada("peteco", "Secret123");

        assertNotEquals("Secret123", almacenada,
                "La contrasena se guardo en texto plano (vulnerable).");
        assertTrue(almacenada.startsWith("$2"),
                "La contrasena no es un hash bcrypt (almacenamiento reversible, vulnerable): "
                        + almacenada);
    }

    @Test
    void dos_passwords_iguales_con_hashes_distintos_por_salt() {
        String h1 = registrarYObtenerContrasenaGuardada("user1", "MismaClave123");
        String h2 = registrarYObtenerContrasenaGuardada("user2", "MismaClave123");

        assertNotEquals(h1, h2,
                "Dos contrasenas iguales produjeron el mismo valor almacenado "
                        + "(sin salt, deterministico, vulnerable).");
    }
}
