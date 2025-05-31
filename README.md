# FluxAuth

## English
FluxAuth is a robust authentication library for C++ applications that provides secure authentication mechanisms and features.

### Features
- Secure authentication system
- Built-in cryptographic functions using Crypto++
- HTTP requests support via libcurl
- Compression utilities with zlib
- Easy integration with existing C++ projects
- Local variable management with encryption support
- Webhook integration
- Hardware ID (HWID) management
- License management system
- Variable and file storage system

### Requirements
- C++ compiler with C++11 support
- Visual Studio (recommended)
- CMake 3.10 or higher

### Installation
1. Add the FluxAuth library files to your project
2. Include the required headers
3. Link against the following libraries:
   - FluxAuth.lib
   - libcurl.lib
   - zlib.lib
   - cryptopp.lib

### Usage
```cpp
#include "auth.hpp"

// Initialize FluxAuth
FluxAuth::Flux auth("your_app_id", "your_private_key", "AppName", "1.0");
auth.Init();

// Authentication
std::string hwid = FluxAuth::Flux::GetMachineHWID();
if (auth.Authenticate("license_key", hwid)) {
    // Successfully authenticated
}

// License Management
auto licenseInfo = auth.GetLicenseInfo();
int64_t expiryTime = auth.GetExpiryTime();

// Variable Management
auth.CreateVariable("user_level", "premium");
auth.CreateVariable("is_admin", true);
std::string level = auth.GetStringVariable("user_level");

// Local Variables
auth.SetLocalVar("settings", "custom_value");
auth.SetLocalVar("count", 42);
if (auto value = auth.GetLocalString("settings")) {
    // Use value
}

// File Management
std::vector<uint8_t> fileData = auth.DownloadFile("resource_name");

// Webhook Integration
auth.SetWebhookUrl("your_webhook_url");
auth.SendWebhook("Event notification");
```

---

## Français
FluxAuth est une bibliothèque d'authentification robuste pour les applications C++ qui fournit des mécanismes et fonctionnalités d'authentification sécurisés.

### Fonctionnalités
- Système d'authentification sécurisé
- Fonctions cryptographiques intégrées utilisant Crypto++
- Support des requêtes HTTP via libcurl
- Utilitaires de compression avec zlib
- Intégration facile avec les projets C++ existants
- Gestion des variables locales avec support de chiffrement
- Intégration de webhooks
- Gestion des identifiants matériels (HWID)
- Système de gestion des licences
- Système de stockage de variables et de fichiers

### Prérequis
- Compilateur C++ avec support C++11
- Visual Studio (recommandé)
- CMake 3.10 ou supérieur

### Installation
1. Ajoutez les fichiers de la bibliothèque FluxAuth à votre projet
2. Incluez les en-têtes nécessaires
3. Liez avec les bibliothèques suivantes :
   - FluxAuth.lib
   - libcurl.lib
   - zlib.lib
   - cryptopp.lib

### Utilisation
```cpp
#include "auth.hpp"

// Initialisation de FluxAuth
FluxAuth::Flux auth("votre_app_id", "votre_cle_privee", "NomApp", "1.0");
auth.Init();

// Authentification
std::string hwid = FluxAuth::Flux::GetMachineHWID();
if (auth.Authenticate("cle_licence", hwid)) {
    // Authentification réussie
}

// Gestion des licences
auto licenseInfo = auth.GetLicenseInfo();
int64_t tempsExpiration = auth.GetExpiryTime();

// Gestion des variables
auth.CreateVariable("niveau_utilisateur", "premium");
auth.CreateVariable("est_admin", true);
std::string niveau = auth.GetStringVariable("niveau_utilisateur");

// Variables locales
auth.SetLocalVar("parametres", "valeur_personnalisee");
auth.SetLocalVar("compteur", 42);
if (auto valeur = auth.GetLocalString("parametres")) {
    // Utiliser la valeur
}

// Gestion des fichiers
std::vector<uint8_t> donneesFichier = auth.DownloadFile("nom_ressource");

// Intégration Webhook
auth.SetWebhookUrl("votre_url_webhook");
auth.SendWebhook("Notification d'événement");
``` 