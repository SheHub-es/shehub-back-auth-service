# SheHub — Auth Service

**Part of the SheHub platform — empowering women through tech, community, and growth.**
SheHub is a digital platform designed to connect, inspire, and support women in their personal and professional journeys.

This repository contains the Authentication microservice, responsible for managing authentication and autorizations within the SheHub ecosystem, including support for email/password login and third-party providers like Google.

🌐 [Visit our teaser page](http://www.shehub.es)

---

## 🧩 Service Overview
This microservice is  a foundational component of the SheHub backend. It handles logic and data for:

User registration and login (email & password)

JWT-based authentication and session management via cookies

OAuth2 login with Google (as an additional convenience feature)

Token validation and user identity resolution using UUIDs

Role-based access control (RBAC)

This service is built with Java, Spring Boot, and PostgreSQL, and is designed for modular, scalable deployment.

⚠️ Status: Currently in early development.

---

## ⚙️ Tech Stack

- **Java 21**
- **Spring Boot 3**
- **Spring Security (JWT)**
- **Spring Data JPA**
- **PostgreSQL**
- **Dotenv for environment config**
- **Lombok for boilerplate reduction**
- **REST API (event-based messaging planned)**

---

## 🔗 Related Services

This macroservice is part of the broader SheHub platform and works alongside:
- user-project-service – manages user profiles and associated data using UUIDs

Other future services may include:
- Notification service
- Team collaboration service
- Messaging service

## 🧱 Architectural Context
SheHub is built using a macroservices approach - splitting functionality across a few well-scoped services. This service is responsible for all authentication flows and secure access management across the platform.

Communication between services (e.g., with user-project-service) happens via REST or planned message queues like Kafka or RabbitMQ.

---

## 🧑‍💻 Contributing
This project is currently under internal development. External contributions may be welcome in the future — stay tuned!

---

## 📄 License
TBD — the license will be defined as the project stabilizes.

---

## 💌 Contact
If you'd like to get in touch or follow along with the progress:

🌍 Website: www.shehub.es

📧 Email: [info@shehub.es]

🐙 GitHub: [(https://github.com/SheHub-es)] 


