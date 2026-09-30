-- MySQL dump 10.13  Distrib 8.4.3, for Win64 (x86_64)
--
-- Host: localhost    Database: asm_system
-- ------------------------------------------------------
-- Server version	8.4.3

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `users`
--

DROP TABLE IF EXISTS `users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `users` (
  `id` int unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(80) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(120) COLLATE utf8mb4_unicode_ci NOT NULL,
  `first_name` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `last_name` varchar(80) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `password_hash` varchar(128) COLLATE utf8mb4_unicode_ci NOT NULL,
  `role` varchar(30) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'cybersecurity_analyst',
  `is_active_flag` tinyint(1) NOT NULL DEFAULT '1',
  `created_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_users_username` (`username`),
  UNIQUE KEY `uq_users_email` (`email`),
  CONSTRAINT `chk_users_role` CHECK ((`role` in (_utf8mb4'it_admin',_utf8mb4'cybersecurity_analyst',_utf8mb4'security_team',_utf8mb4'threat_intel_analyst')))
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `users`
--

LOCK TABLES `users` WRITE;
/*!40000 ALTER TABLE `users` DISABLE KEYS */;
INSERT INTO `users` VALUES (1,'admin','admin@example.com',NULL,NULL,'$2b$12$0WOnw7VdCdl7CPuCbklqIeCSiFLIBaPjfbCxJBI4ABE.I6IPEnoiq','it_admin',1,'2026-08-09 22:37:26'),(3,'kimmcondones7','luqmanulhakim1113@gmail.com','Luqmanul','Hakim','$2b$12$QoRH7PlkQ/kKqlnzjfQ/MuhJZqUCpYum9WPk52oE855pL4LLk95TW','cybersecurity_analyst',1,'2026-08-10 03:31:13'),(4,'Luqmanulhakim','kl2405016003@student.uptm.edu.my','Hakim','Kamarul','$2b$12$IFYEg9RB3SiqyhIzeb00yemYK1odRS809ezGFGbfITHKluP/ed146','threat_intel_analyst',1,'2026-08-10 03:48:39'),(5,'otptester2','otptester2@example.com','Otp','Tester','$2b$12$RiNUs1LNhFgT.kHBsqfRD.YcyfIDSKEt9PkLclxZJfydckY1NmzzW','cybersecurity_analyst',1,'2026-08-16 15:00:14'),(6,'roleadmin1','roleadmin1@example.com','Role','Admin','$2b$12$XJrWKymKf0wn8ypdd7AEruE9mRAwHTz7azUdZVYduW9QaJgOzi4sS','it_admin',1,'2026-08-16 17:19:09'),(9,'kimmik1','ahwenvagarry@gmail.com','kimm','kimmik','$2b$12$gu0HC/HNChNzHfsTmr9xk.wIvFsBSkVoGsA1C48No.Nimq8hUqcxy','cybersecurity_analyst',1,'2026-08-16 20:39:58'),(10,'fauzansim1','fauzan.wasim135@gmail.com','fauzan','wasim','$2b$12$Cr8a/kGYZcHjiR1Xa3DwfewisnFzUjfCLjOqjsVS7O8TK7T/casiy','security_team',1,'2026-08-18 05:18:46'),(11,'fawaz1','kl2405016001@student.uptm.edu.my','fawwaz','wasim','$2b$12$9G0g4lSVcGMCJ2j1cn7u0OFjGmFXswpVZyU2dtumN8JPSX69kBKrG','threat_intel_analyst',1,'2026-08-18 05:20:46');
/*!40000 ALTER TABLE `users` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2026-10-01  3:09:39
