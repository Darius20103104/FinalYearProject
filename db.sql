-- --------------------------------------------------------
-- Host:                         127.0.0.1
-- Server version:               12.0.2-MariaDB - mariadb.org binary distribution
-- Server OS:                    Win64
-- HeidiSQL Version:             12.13.0.7147
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;


-- Dumping database structure for system_checker
CREATE DATABASE IF NOT EXISTS `system_checker` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;
USE `system_checker`;

-- Dumping structure for table system_checker.expected_checks
CREATE TABLE IF NOT EXISTS `expected_checks` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `check_type` enum('registry','port','file','service','custom','software') NOT NULL DEFAULT 'registry',
  `reg_path` varchar(512) DEFAULT NULL,
  `reg_value_name` varchar(255) DEFAULT NULL,
  `check_name` varchar(255) NOT NULL,
  `expected_value` varchar(255) DEFAULT NULL,
  `condition` enum('equals','not_exists','contains','exists','regex','eq','ne','gt','lt','ge','le') DEFAULT 'equals',
  `note` text DEFAULT NULL,
  `category` varchar(255) DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT current_timestamp(),
  `updated_at` timestamp NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uq_check_name_type` (`check_type`,`check_name`),
  KEY `idx_check_type` (`check_type`),
  KEY `idx_category` (`category`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Dumping data for table system_checker.expected_checks: ~22 rows (approximately)
REPLACE INTO `expected_checks` (`id`, `check_type`, `reg_path`, `reg_value_name`, `check_name`, `expected_value`, `condition`, `note`, `category`, `created_at`, `updated_at`) VALUES
	(1, 'registry', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management', 'FeatureSettingsOverride', 'FeatureSettingsOverride', '0', 'equals', 'Should be 0 or not exist', 'Memory Management', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(2, 'registry', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management', 'FeatureSettingsOverrideMask', 'FeatureSettingsOverrideMask', '0', 'equals', 'Should be 0 or not exist', 'Memory Management', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(3, 'registry', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power', 'HiberbootEnabled', 'FastStartupDisabled', '0', 'equals', 'Fast startup should be disabled', 'Power Management', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(4, 'registry', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FileSystem', 'NtfsDisable8dot3NameCreation', 'NtfsDisable8dot3NameCreation', '1', 'equals', 'Should be set to 1', 'File System', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(5, 'registry', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FileSystem', 'NtfsDisableLastAccessUpdate', 'NtfsDisableLastAccessUpdate', '2147483649', 'equals', 'Should be set to 2147483649 (0x80000001)', 'File System', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(6, 'registry', 'HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer', 'DelaySendToMenuBuild', 'DelaySendToMenuBuild', '1', 'equals', 'Should be set to 1', 'Explorer', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(7, 'registry', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FileSystem', 'LongPathsEnabled', 'LongPathsEnabled', '1', 'equals', 'Should be set to 1', 'File System', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(8, 'registry', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters', 'EnablePrefetcher', 'EnablePrefetcher', '0', 'equals', 'Should be 2 to Enable only boot time Prefetching', 'Performance', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(9, 'registry', 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters', 'EnableSuperfetcher', 'EnableSuperfetcher', '0', 'equals', 'Should be 0 to disable Superfetcher', 'Performance', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(10, 'port', NULL, NULL, 'port_80', '80', 'not_exists', 'HTTP | For hosting web server', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(11, 'port', NULL, NULL, 'port_443', '443', 'not_exists', 'HTTPS | For hosting secure web server', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(12, 'port', NULL, NULL, 'port_21', '21', 'not_exists', 'FTP | For file transfer', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(13, 'port', NULL, NULL, 'port_22', '22', 'not_exists', 'SSH | For secure remote access', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(14, 'port', NULL, NULL, 'port_23', '23', 'not_exists', 'Telnet | For unsecured remote login', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(15, 'port', NULL, NULL, 'port_25', '25', 'not_exists', 'SMTP | For sending email', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(16, 'port', NULL, NULL, 'port_53', '53', 'not_exists', 'DNS | For domain name resolution', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(17, 'port', NULL, NULL, 'port_110', '110', 'not_exists', 'POP3 | For retrieving email', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(18, 'port', NULL, NULL, 'port_143', '143', 'not_exists', 'IMAP | For accessing email on server', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(19, 'port', NULL, NULL, 'port_445', '445', 'not_exists', 'SMB | For Windows file and printer sharing', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(20, 'port', NULL, NULL, 'port_3389', '3389', 'not_exists', 'RDP | Remote Desktop Protocol - high-risk if unused', 'Network', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(21, 'software', NULL, NULL, 'Notepad++', '8.7.5', 'ge', 'Version of at least 8.7.5', 'Software', '2026-02-13 00:22:55', '2026-02-13 00:22:55'),
	(22, 'software', NULL, NULL, 'vlc', '3.0.6', 'le', 'Version of less than 3.0.6', 'Software', '2026-02-13 00:22:55', '2026-02-13 00:22:55');

/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40111 SET SQL_NOTES=IFNULL(@OLD_SQL_NOTES, 1) */;
