-- phpMyAdmin SQL Dump
-- version 5.1.0
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 17-09-2022 a las 05:02:39
-- Versión del servidor: 10.4.18-MariaDB
-- Versión de PHP: 8.0.3

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `epayco`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `ci_sessions`
--

CREATE TABLE `ci_sessions` (
  `id` varchar(128) COLLATE utf8_spanish_ci NOT NULL,
  `ip_address` varchar(45) COLLATE utf8_spanish_ci NOT NULL,
  `timestamp` int(10) UNSIGNED NOT NULL DEFAULT 0,
  `data` blob NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_spanish_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `j081t_wallet`
--

CREATE TABLE `j081t_wallet` (
  `id` int(11) NOT NULL,
  `co_usuario` int(11) DEFAULT NULL,
  `ca_saldo` double DEFAULT 0,
  `in_activo` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `lu_app`
--

CREATE TABLE `lu_app` (
  `id` int(11) NOT NULL,
  `nb_aplicacion` varchar(100) COLLATE utf8_spanish_ci DEFAULT NULL,
  `token` varchar(100) COLLATE utf8_spanish_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_spanish_ci;

--
-- Volcado de datos para la tabla `lu_app`
--

INSERT INTO `lu_app` (`id`, `nb_aplicacion`, `token`) VALUES
(1, 'Administrador Login Unico', '43e141129c319f4bb639d06b7affa032'),
(2, 'medinet', '43e141129c319f4bb639d06b7affa0d1');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `lu_groups`
--

CREATE TABLE `lu_groups` (
  `id` int(11) NOT NULL,
  `name` varchar(50) COLLATE utf8_spanish_ci DEFAULT NULL,
  `description` varchar(100) COLLATE utf8_spanish_ci DEFAULT NULL,
  `app_id` int(11) DEFAULT NULL,
  `in_activo` tinyint(1) DEFAULT 1,
  `flag_mysql` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_spanish_ci;

--
-- Volcado de datos para la tabla `lu_groups`
--

INSERT INTO `lu_groups` (`id`, `name`, `description`, `app_id`, `in_activo`, `flag_mysql`) VALUES
(1, 'ADMIN', 'ADMINISTRADOR LOGIN UNICO', 1, 1, 1),
(5, 'ADMIN_MEDINET', 'SISTEMA MEDINET', 2, 1, 5),
(6, 'ADMINISTRADOR', 'ADMINISTRADOR', 2, 1, 6),
(7, 'USUARIO EMPRESA', 'USUARIO EMPRESA', NULL, 1, NULL),
(8, 'USUARIO', 'USUARIO NORMAL', 0, 1, NULL);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `lu_login_attempts`
--

CREATE TABLE `lu_login_attempts` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(15) COLLATE utf8_spanish_ci DEFAULT NULL,
  `login` varchar(100) COLLATE utf8_spanish_ci NOT NULL,
  `time` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_spanish_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `lu_users`
--

CREATE TABLE `lu_users` (
  `id` int(11) NOT NULL,
  `ip_address` varchar(15) COLLATE utf8_spanish_ci DEFAULT NULL,
  `username` varchar(100) COLLATE utf8_spanish_ci DEFAULT NULL,
  `first_name` varchar(50) COLLATE utf8_spanish_ci DEFAULT NULL,
  `last_name` varchar(50) COLLATE utf8_spanish_ci DEFAULT NULL,
  `nb_nacionalidad` varchar(10) COLLATE utf8_spanish_ci DEFAULT NULL,
  `nu_documento` varchar(20) COLLATE utf8_spanish_ci DEFAULT NULL,
  `password` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `email` varchar(100) COLLATE utf8_spanish_ci DEFAULT NULL,
  `salt` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `activation_code` varchar(40) COLLATE utf8_spanish_ci DEFAULT NULL,
  `forgotten_password_code` varchar(40) COLLATE utf8_spanish_ci DEFAULT NULL,
  `forgotten_password_time` int(11) DEFAULT NULL,
  `remember_code` varchar(40) COLLATE utf8_spanish_ci DEFAULT NULL,
  `created_on` int(11) DEFAULT NULL,
  `last_login` int(11) DEFAULT NULL,
  `ff_nacimiento` date DEFAULT NULL,
  `phone` varchar(20) COLLATE utf8_spanish_ci DEFAULT NULL,
  `nu_whatsapp` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `in_verificacion` varchar(20) COLLATE utf8_spanish_ci DEFAULT NULL,
  `ff_verificacion` date DEFAULT NULL,
  `nu_intentos` int(11) DEFAULT NULL,
  `attempt_time` int(11) DEFAULT NULL,
  `active` int(11) DEFAULT NULL,
  `tx_link` varchar(1000) COLLATE utf8_spanish_ci DEFAULT NULL,
  `in_verificado` tinyint(1) DEFAULT 1,
  `nb_foto_perfil` varchar(500) COLLATE utf8_spanish_ci DEFAULT NULL,
  `nu_celular` int(11) DEFAULT NULL,
  `tx_token` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `time_duration_token` int(11) DEFAULT 0
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_spanish_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `lu_users_groups`
--

CREATE TABLE `lu_users_groups` (
  `id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `group_id` int(11) DEFAULT NULL,
  `in_activo` tinyint(1) DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_spanish_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `lu_users_sessions`
--

CREATE TABLE `lu_users_sessions` (
  `id` int(11) NOT NULL,
  `id_session` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `ip` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `nb_navegador` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `nb_os` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `tx_agente` varchar(255) COLLATE utf8_spanish_ci DEFAULT NULL,
  `co_usuario` int(11) DEFAULT NULL,
  `ff_ultima_actividad_time` int(11) DEFAULT NULL,
  `ff_registro_time` int(11) DEFAULT NULL,
  `nb_estatus` enum('Conectado','Desconectado') COLLATE utf8_spanish_ci NOT NULL DEFAULT 'Conectado',
  `in_activo` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COLLATE=utf8_spanish_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `sessions`
--

CREATE TABLE `sessions` (
  `ip_address` varchar(50) COLLATE utf8_spanish_ci DEFAULT NULL,
  `timestamp` varchar(100) COLLATE utf8_spanish_ci DEFAULT NULL,
  `data` varchar(100) COLLATE utf8_spanish_ci DEFAULT NULL,
  `id` text COLLATE utf8_spanish_ci DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_spanish_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `x001t_wallet_linea`
--

CREATE TABLE `x001t_wallet_linea` (
  `id` int(11) NOT NULL,
  `co_wallet` int(11) DEFAULT NULL,
  `co_usuario` int(11) DEFAULT NULL,
  `ca_monto` double DEFAULT NULL,
  `nb_operacion` enum('CREDITO','DEBITO','','') DEFAULT NULL,
  `ff_sistema` datetime DEFAULT current_timestamp(),
  `tx_concepto` varchar(255) DEFAULT NULL,
  `in_activo` tinyint(1) NOT NULL DEFAULT 1
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `ci_sessions`
--
ALTER TABLE `ci_sessions`
  ADD KEY `ci_sessions_timestamp` (`timestamp`);

--
-- Indices de la tabla `j081t_wallet`
--
ALTER TABLE `j081t_wallet`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `lu_app`
--
ALTER TABLE `lu_app`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `lu_groups`
--
ALTER TABLE `lu_groups`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `lu_login_attempts`
--
ALTER TABLE `lu_login_attempts`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `lu_users`
--
ALTER TABLE `lu_users`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `lu_users_groups`
--
ALTER TABLE `lu_users_groups`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `lu_users_sessions`
--
ALTER TABLE `lu_users_sessions`
  ADD PRIMARY KEY (`id`);

--
-- Indices de la tabla `x001t_wallet_linea`
--
ALTER TABLE `x001t_wallet_linea`
  ADD PRIMARY KEY (`id`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `j081t_wallet`
--
ALTER TABLE `j081t_wallet`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `lu_app`
--
ALTER TABLE `lu_app`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- AUTO_INCREMENT de la tabla `lu_groups`
--
ALTER TABLE `lu_groups`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- AUTO_INCREMENT de la tabla `lu_login_attempts`
--
ALTER TABLE `lu_login_attempts`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `lu_users`
--
ALTER TABLE `lu_users`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `lu_users_groups`
--
ALTER TABLE `lu_users_groups`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `lu_users_sessions`
--
ALTER TABLE `lu_users_sessions`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `x001t_wallet_linea`
--
ALTER TABLE `x001t_wallet_linea`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
