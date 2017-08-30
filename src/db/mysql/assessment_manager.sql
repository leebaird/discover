-- phpMyAdmin SQL Dump
-- version 4.7.3
-- https://www.phpmyadmin.net/
--
-- Host: localhost
-- Generation Time: Aug 30, 2017 at 07:12 PM
-- Server version: 10.1.25-MariaDB
-- PHP Version: 5.6.31

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `assessment_manager`
--

-- --------------------------------------------------------

--
-- Table structure for table `accountmgrs`
--

CREATE TABLE `accountmgrs` (
  `accountmgrID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `accountmgr` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `cell` varchar(12) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `email` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `notes` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `clients`
--

CREATE TABLE `clients` (
  `clientID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `client` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `notes` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `employeeID` int(4) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `contacts`
--

CREATE TABLE `contacts` (
  `contactID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `contact` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `title` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `work` varchar(20) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `cell` varchar(12) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `email` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `notes` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `clientID` int(4) NOT NULL,
  `projectID` int(4) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `employees`
--

CREATE TABLE `employees` (
  `employeeID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `employee` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `title` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `type` varchar(10) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `accountmgr` varchar(3) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `projectmgr` varchar(3) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `cell` varchar(12) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `email` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `notes` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `projectID` int(4) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `findings`
--

CREATE TABLE `findings` (
  `findingID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `type` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `finding` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `observation` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `severity` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `remediation` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `see_also` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `hostvulns`
--

CREATE TABLE `hostvulns` (
  `hostvulnID` int(6) NOT NULL,
  `modified` datetime NOT NULL,
  `tool` varchar(16) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `vulnerability` varchar(128) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `findingID` int(3) NOT NULL,
  `cvss_base` int(2) NOT NULL,
  `internal` varchar(8) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `external` varchar(8) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `remediation` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `see_also` point NOT NULL,
  `published` date NOT NULL,
  `updated` date NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `projectmgrs`
--

CREATE TABLE `projectmgrs` (
  `projectmgrID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `projectmgr` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `cell` varchar(12) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `email` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `notes` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `projectID` int(4) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `projects`
--

CREATE TABLE `projects` (
  `projectID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `project` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `client` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `accountmgr` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `projectmgr` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `employee` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `type` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `objective` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `billing` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `rate` varchar(10) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `address1` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `address2` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `city` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `state` varchar(2) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `zip` varchar(10) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `kickoff` date NOT NULL,
  `start` date NOT NULL,
  `finish` date NOT NULL,
  `hours` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `tech_qa` date NOT NULL,
  `draft_delivery` date NOT NULL,
  `client_comments` date NOT NULL,
  `final_delivery` date NOT NULL,
  `status` varchar(10) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `notes` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `hold` date NOT NULL,
  `restart` date NOT NULL,
  `percent_complete` varchar(3) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `complete` varchar(5) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `scan`
--

CREATE TABLE `scan` (
  `scanID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `scan` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `location` varchar(10) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `severity` varchar(10) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `ip_address` varchar(15) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `fqdn` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `os` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `port` int(5) NOT NULL,
  `proof` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `date` date NOT NULL,
  `projectID` int(4) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `userID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `username` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `email` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `password` varchar(128) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `salt` varchar(128) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `activated` tinyint(1) NOT NULL,
  `role` varchar(25) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `approved` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `vulnerabilities`
--

CREATE TABLE `vulnerabilities` (
  `vulnerabilityID` int(5) NOT NULL,
  `modified` datetime NOT NULL,
  `vulnerability` varchar(100) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `solution` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `cvss_base_score` decimal(3,1) NOT NULL,
  `see_also` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `cve` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `internal` varchar(10) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `external` varchar(10) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `scanID` int(4) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

-- --------------------------------------------------------

--
-- Table structure for table `webvulns`
--

CREATE TABLE `webvulns` (
  `webvulnID` int(4) NOT NULL,
  `modified` datetime NOT NULL,
  `tool` varchar(16) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `vulnerability` varchar(50) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `findingID` int(3) NOT NULL,
  `severity` varchar(8) CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `description` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `remediation` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL,
  `see_also` text CHARACTER SET utf8 COLLATE utf8_bin NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `accountmgrs`
--
ALTER TABLE `accountmgrs`
  ADD PRIMARY KEY (`accountmgrID`);

--
-- Indexes for table `clients`
--
ALTER TABLE `clients`
  ADD PRIMARY KEY (`clientID`);

--
-- Indexes for table `contacts`
--
ALTER TABLE `contacts`
  ADD PRIMARY KEY (`contactID`);

--
-- Indexes for table `employees`
--
ALTER TABLE `employees`
  ADD PRIMARY KEY (`employeeID`);

--
-- Indexes for table `findings`
--
ALTER TABLE `findings`
  ADD PRIMARY KEY (`findingID`);

--
-- Indexes for table `hostvulns`
--
ALTER TABLE `hostvulns`
  ADD PRIMARY KEY (`hostvulnID`);

--
-- Indexes for table `projectmgrs`
--
ALTER TABLE `projectmgrs`
  ADD PRIMARY KEY (`projectmgrID`);

--
-- Indexes for table `projects`
--
ALTER TABLE `projects`
  ADD PRIMARY KEY (`projectID`);

--
-- Indexes for table `scan`
--
ALTER TABLE `scan`
  ADD PRIMARY KEY (`scanID`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`userID`);

--
-- Indexes for table `vulnerabilities`
--
ALTER TABLE `vulnerabilities`
  ADD PRIMARY KEY (`vulnerabilityID`);

--
-- Indexes for table `webvulns`
--
ALTER TABLE `webvulns`
  ADD PRIMARY KEY (`webvulnID`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `accountmgrs`
--
ALTER TABLE `accountmgrs`
  MODIFY `accountmgrID` int(4) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `clients`
--
ALTER TABLE `clients`
  MODIFY `clientID` int(4) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
--
-- AUTO_INCREMENT for table `contacts`
--
ALTER TABLE `contacts`
  MODIFY `contactID` int(4) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
--
-- AUTO_INCREMENT for table `employees`
--
ALTER TABLE `employees`
  MODIFY `employeeID` int(4) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;
--
-- AUTO_INCREMENT for table `findings`
--
ALTER TABLE `findings`
  MODIFY `findingID` int(4) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
--
-- AUTO_INCREMENT for table `hostvulns`
--
ALTER TABLE `hostvulns`
  MODIFY `hostvulnID` int(6) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;
--
-- AUTO_INCREMENT for table `projectmgrs`
--
ALTER TABLE `projectmgrs`
  MODIFY `projectmgrID` int(4) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `projects`
--
ALTER TABLE `projects`
  MODIFY `projectID` int(4) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `scan`
--
ALTER TABLE `scan`
  MODIFY `scanID` int(4) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `userID` int(4) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;
--
-- AUTO_INCREMENT for table `vulnerabilities`
--
ALTER TABLE `vulnerabilities`
  MODIFY `vulnerabilityID` int(5) NOT NULL AUTO_INCREMENT;
--
-- AUTO_INCREMENT for table `webvulns`
--
ALTER TABLE `webvulns`
  MODIFY `webvulnID` int(4) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
