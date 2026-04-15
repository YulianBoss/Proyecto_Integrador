const db = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 🔥 REGISTRO
const register = async (req, res) => {
    const { nombre_completo, correo, password, rol, num_identificacion, telefono } = req.body;

    // ✅ Validación de campos obligatorios
    if (!nombre_completo || !correo || !password || !rol) {
        return res.status(400).json({ message: 'Faltan datos obligatorios' });
    }

    // ✅ No permitir admin
    if (rol === 'admin') {
        return res.status(403).json({ message: 'No puedes registrarte como administrador' });
    }

    // ✅ Validación contraseña básica
    if (password.length < 6) {
        return res.status(400).json({ message: 'La contraseña debe tener mínimo 6 caracteres' });
    }

    try {
        // ✅ Validar correo único
        const checkQuery = `SELECT id FROM usuarios WHERE correo = ?`;

        db.query(checkQuery, [correo], async (err, results) => {
            if (err) {
                console.error(err);
                return res.status(500).json({ message: 'Error del servidor' });
            }

            if (results.length > 0) {
                return res.status(400).json({ message: 'El correo ya está registrado' });
            }

            // 🔐 Hash contraseña
            const hashedPassword = await bcrypt.hash(password, 10);

            // ✅ Estado por defecto = pendiente
            const estado = 'pendiente';

            const insertQuery = `
                INSERT INTO usuarios 
                (nombre_completo, correo, contrasena_hash, rol, estado, num_identificacion, telefono)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            `;

            db.query(insertQuery, [
                nombre_completo,
                correo,
                hashedPassword,
                rol,
                estado,
                num_identificacion || null,
                telefono || null
            ], (err) => {
                if (err) {
                    console.error(err);
                    return res.status(500).json({ message: 'Error al registrar usuario' });
                }

                res.status(201).json({
                    message: 'Usuario registrado (pendiente de aprobación) ✅'
                });
            });
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'Error del servidor' });
    }
};

// 🔐 LOGIN
const login = (req, res) => {
    const { correo, password } = req.body;

    if (!correo || !password) {
        return res.status(400).json({ message: 'Faltan datos' });
    }

    const query = `SELECT * FROM usuarios WHERE correo = ?`;

    db.query(query, [correo], async (err, results) => {
        if (err) {
            console.error(err);
            return res.status(500).json({ message: 'Error del servidor' });
        }

        if (results.length === 0) {
            return res.status(400).json({ message: 'Usuario no encontrado' });
        }

        const user = results[0];

        // 🔴 Validar estado (RF-01 CLAVE)
        if (user.estado !== 'activo') {
            return res.status(403).json({ message: 'Usuario no aprobado aún' });
        }

        const validPassword = await bcrypt.compare(password, user.contrasena_hash);

        if (!validPassword) {
            return res.status(400).json({ message: 'Contraseña incorrecta' });
        }

        // 🔥 JWT
        const token = jwt.sign(
            { id: user.id, rol: user.rol },
            process.env.JWT_SECRET,
            { expiresIn: '2h' }
        );

        res.json({
            message: 'Login exitoso ✅',
            token,
            user: {
                id: user.id,
                nombre: user.nombre_completo,
                rol: user.rol
            }
        });
    });
};

module.exports = { register, login };