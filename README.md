# ARP-repositorio# 🔵 ARP MitM Attack - Man-in-the-Middle via ARP Spoofing

**Autor:** Maitte Rodriguez
**Matrícula:** 20241165
**Fecha:** Febrero 2026  
**Curso:** Seguridad de Redes

---

## ⚠️ ADVERTENCIA LEGAL

Este proyecto es **exclusivamente para fines educativos** en entornos de laboratorio controlados. El uso de estas técnicas en redes sin autorización expresa es **ILEGAL** y constituye un delito federal en la mayoría de los países.

**NO utilices este código para:**
- Interceptar comunicaciones sin consentimiento
- Robar información confidencial
- Realizar fraudes o estafas
- Cualquier actividad maliciosa

**El uso indebido puede resultar en:**
- Cargos criminales
- Prisión
- Multas significativas
- Responsabilidad civil

---

## 📋 Descripción

Este script implementa un ataque **Man-in-the-Middle (MitM)** mediante **ARP Spoofing** (envenenamiento de caché ARP). El ataque permite al atacante posicionarse entre la víctima y el gateway, interceptando todo el tráfico de red que pasa entre ellos.

### ¿Cómo funciona?

1. **Descubrimiento:** El atacante identifica las direcciones MAC de la víctima y el gateway
2. **Envenenamiento:** Envía paquetes ARP falsos a ambos extremos
3. **Interceptación:** Todo el tráfico entre víctima y gateway pasa por el atacante
4. **Forwarding:** El atacante reenvía los paquetes para mantener la conectividad

---

## 🎯 Objetivos de Aprendizaje

1. Comprender el protocolo ARP y sus vulnerabilidades
2. Implementar técnicas de Man-in-the-Middle
3. Aprender a detectar y prevenir ataques ARP Spoofing
4. Analizar tráfico interceptado con Wireshark
5. Implementar medidas de seguridad de capa 2

---

## 🏗️ Topología de Red
<img width="806" height="954" alt="image" src="https://github.com/user-attachments/assets/a7cb006d-c34f-4449-ae16-d9096081fed3" />



```

### Configuración de Red

**Router R1 (Gateway):**
- IP: 11.6.5.1/24
- Interfaz: GigabitEthernet0/0/12

**Switch:**
- Gi0/0: Trunk al Router
- Gi0/2: Access port → Kali Linux (e0)
- Gi0/1: Access port → Ubuntu Víctima (e0)

**Kali Linux (Atacante):**
- IP: 11.6.5.10/24
- Gateway: 11.6.5.1
- Interfaz: eth0

**Ubuntu (Víctima):**
- IP: 11.6.5.12/24
- Gateway: 11.6.5.1
- Interfaz: eth0

---

## 🛠️ Requisitos del Sistema

### Software Necesario

- **Sistema Operativo:** Kali Linux 2023.x o superior
- **Python:** 3.8+
- **Scapy:** Framework de manipulación de paquetes
- **Wireshark:** Análisis de tráfico
- **dsniff** (opcional): Herramientas adicionales de análisis

### Hardware Recomendado

- **CPU:** 2 cores mínimo
- **RAM:** 2GB mínimo
- **Interfaz de red:** Ethernet

---

## 📦 Instalación

### 1. Clonar el Repositorio

```bash
git clone https://github.com/[tu-usuario]/arp-mitm-attack.git
cd arp-mitm-attack
```

### 2. Instalar Dependencias

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Python y pip
sudo apt install python3 python3-pip -y

# Instalar Scapy
sudo pip3 install scapy --break-system-packages

# Instalar herramientas adicionales (opcional)
sudo apt install wireshark dsniff net-tools -y

# Verificar instalación
python3 -c "from scapy.all import *; print('✓ Scapy instalado correctamente')"
```

### 3. Dar Permisos de Ejecución

```bash
chmod +x arp_mitm_attack.py
```

---

## 🚀 Uso del Script

### Paso 1: Habilitar IP Forwarding

**MUY IMPORTANTE:** Para que el tráfico fluya correctamente, debes habilitar el reenvío de paquetes IP:

```bash
# Habilitar IP forwarding
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward

# Verificar (debe mostrar 1)
cat /proc/sys/net/ipv4/ip_forward

# Para hacerlo permanente (opcional)
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Paso 2: Configurar el Script

Edita `arp_mitm_attack.py` para ajustar los parámetros:

```python
# Configuración según tu topología
VICTIM_IP = "11.6.5.12"    # IP de la máquina víctima
GATEWAY_IP = "11.6.5.1"    # IP del router/gateway
INTERFACE = "eth0"         # Interfaz de red de Kali
```

### Paso 3: Ejecutar el Ataque

```bash
# Ejecutar con privilegios de root
sudo python3 arp_mitm_attack.py
```

### Salida Esperada

```
=== ATAQUE MITM MEDIANTE ARP SPOOFING ===
ADVERTENCIA: Solo para fines educativos en laboratorios controlados
NOTA: Necesitas habilitar el forwarding de IPs para interceptar tráfico

[*] Iniciando ataque MitM mediante ARP Spoofing
[*] Víctima: 11.6.5.12
[*] Gateway: 11.6.5.1
[*] Interfaz: eth0
[*] Presiona Ctrl+C para detener y restaurar

[+] MAC Víctima (11.6.5.12): aa:bb:cc:dd:ee:01
[+] MAC Gateway (11.6.5.1): aa:bb:cc:dd:ee:02
[+] Enviando paquetes ARP falsos...

[+] Paquetes ARP enviados: 20
[+] Paquetes ARP enviados: 40
[+] Paquetes ARP enviados: 60
...
```

### Paso 4: Detener el Ataque

Presiona `Ctrl+C` para detener el ataque. El script automáticamente restaurará las tablas ARP:

```
^C
[!] Restaurando tablas ARP...
[✓] ARP restaurado para 11.6.5.12
[✓] ARP restaurado para 11.6.5.1
[✓] Total paquetes ARP enviados: 128
```

---

## 🔍 Verificación del Ataque

### En la Máquina Víctima (Ubuntu)

**Ver tabla ARP antes del ataque:**
```bash
# Método 1
arp -n

# Método 2
ip neigh show

# Salida normal:
# 11.6.5.1    ether   50:00:00:01:00:00   C   eth0  ← MAC real del gateway
```

**Durante el ataque:**
```bash
# Monitorear en tiempo real
watch -n 1 arp -n

# Salida envenenada:
# 11.6.5.1    ether   50:00:00:0A:00:00   C   eth0  ← MAC del atacante!
```

**Después de restaurar:**
```bash
arp -n
# 11.6.5.1    ether   50:00:00:01:00:00   C   eth0  ← MAC real restaurada
```

### En la Máquina Atacante (Kali)

**Capturar tráfico interceptado:**
```bash
# Terminal 1: Ejecutar el ataque
sudo python3 arp_mitm_attack.py

# Terminal 2: Capturar tráfico
sudo wireshark -i eth0 -k -f "host 11.6.5.12"

# O usar tcpdump
sudo tcpdump -i eth0 -n host 11.6.5.12 -w captura_mitm.pcap
```

---

## 📊 Análisis con Wireshark

### Filtros Útiles

```
# Ver solo paquetes ARP
arp

# Ver paquetes ARP spoofing (duplicados)
arp.duplicate-address-detected

# Ver tráfico de la víctima
ip.addr == 11.6.5.12

# Ver tráfico HTTP no cifrado
http

# Ver credenciales (si existen)
http.request.method == "POST"

# Ver DNS queries
dns

# Detectar ARP spoofing
arp.opcode == 2 && arp.src.proto_ipv4 == 11.6.5.1
```

### Indicadores de Ataque Exitoso

1. **Tráfico duplicado:** El mismo paquete pasa por el atacante
2. **MAC addresses inconsistentes:** Múltiples MACs para la misma IP
3. **TTL decrementado:** Los paquetes tienen un hop adicional
4. **Tráfico visible:** El atacante puede ver contenido no cifrado

---

## 🛡️ Medidas de Mitigación y Defensa

### 1. Static ARP Entries

```bash
# En la víctima, configurar ARP estático
sudo arp -s 11.6.5.1 50:00:00:01:00:00

# Verificar
arp -n
# 11.6.5.1    ether   50:00:00:01:00:00   CM  eth0  ← 'M' = permanente
```

### 2. DAI (Dynamic ARP Inspection) en el Switch

```cisco
! Habilitar DAI en el switch
configure terminal

! Crear ACL para DHCP snooping
ip dhcp snooping
ip dhcp snooping vlan 1

! Habilitar DAI
ip arp inspection vlan 1

! Configurar puertos de confianza
interface GigabitEthernet0/0
 ip dhcp snooping trust
 ip arp inspection trust
 exit

! Puertos de acceso no confiables (automático)
interface range GigabitEthernet0/1-2
 no ip dhcp snooping trust
 no ip arp inspection trust
 exit

end
write memory
```

### 3. Port Security

```cisco
interface GigabitEthernet0/1
 switchport mode access
 switchport port-security
 switchport port-security maximum 1
 switchport port-security mac-address sticky
 switchport port-security violation restrict
 exit
```

### 4. ARPwatch - Monitoreo de ARP

```bash
# Instalar ARPwatch
sudo apt install arpwatch -y

# Configurar y arrancar
sudo systemctl start arpwatch
sudo systemctl enable arpwatch

# Ver logs
sudo tail -f /var/log/syslog | grep arpwatch
```

### 5. Herramientas de Detección

```bash
# XArp - Detector de ARP Spoofing
sudo apt install xarp

# Arpwatch - Monitor de tabla ARP
sudo arpwatch -i eth0

# ArpON - ARP Handler inspectiON
sudo apt install arpon
sudo arpon -d -i eth0
```

---

## 🧪 Conceptos Técnicos

### ¿Qué es ARP?

**Address Resolution Protocol (ARP)** es un protocolo de capa 2 que:
- Resuelve direcciones IP a direcciones MAC
- Opera en redes locales (broadcast domain)
- No tiene autenticación
- Es stateless (sin estado)

### Estructura de un Paquete ARP

```
┌────────────────────┐
│  Ethernet Header   │
├────────────────────┤
│  Hardware Type     │ 0x0001 (Ethernet)
│  Protocol Type     │ 0x0800 (IPv4)
│  HW Addr Length    │ 6 (MAC)
│  Proto Addr Length │ 4 (IPv4)
│  Operation         │ 1=Request, 2=Reply
├────────────────────┤
│  Sender MAC        │
│  Sender IP         │
│  Target MAC        │
│  Target IP         │
└────────────────────┘
```

### ARP Spoofing - Proceso Detallado

**1. Estado Normal:**
```
Víctima ARP Table:
11.6.5.1 → MAC_Gateway (correcta)

Gateway ARP Table:
11.6.5.12 → MAC_Victim (correcta)
```

**2. Ataque Iniciado:**
```
Atacante envía:
→ A Víctima: "11.6.5.1 está en MAC_Atacante" (gratuitous ARP)
→ A Gateway: "11.6.5.12 está en MAC_Atacante" (gratuitous ARP)
```

**3. Estado Envenenado:**
```
Víctima ARP Table:
11.6.5.1 → MAC_Atacante (envenenada!)

Gateway ARP Table:
11.6.5.12 → MAC_Atacante (envenenada!)
```

**4. Flujo de Tráfico:**
```
Víctima → Atacante → Gateway
Gateway → Atacante → Víctima
```

### ¿Por qué funciona?

1. **Sin autenticación:** ARP no verifica la identidad del emisor
2. **Gratuitous ARP:** Actualizaciones no solicitadas son aceptadas
3. **Trust por defecto:** Los sistemas confían en respuestas ARP
4. **Caché volátil:** Las entradas ARP expiran y se actualizan

---

## 📁 Estructura del Proyecto

```
arp-mitm-attack/
│
├── README.md                      # Este archivo
├── arp_mitm_attack.py            # Script principal del ataque
├── requirements.txt               # Dependencias de Python
├── .gitignore                    # Archivos a ignorar
├── LICENSE                       # Licencia MIT
│
├── docs/
│   ├── topologia.png             # Diagrama de la topología
│   ├── router_config.txt         # Configuración del router
│   ├── switch_security.txt       # Configuración de seguridad
│   └── capturas/                 # Capturas de Wireshark
│       ├── arp_normal.pcapng
│       ├── arp_spoofing.pcapng
│       └── traffic_intercepted.pcapng
│
├── screenshots/
│   ├── 01_topologia.png
│   ├── 02_arp_table_before.png
│   ├── 03_attack_running.png
│   ├── 04_arp_table_poisoned.png
│   ├── 05_wireshark_capture.png
│   └── 06_arp_restored.png
│
└── tools/
    ├── detect_arp_spoofing.py    # Script de detección
    └── monitor_arp.sh            # Script de monitoreo
```

---

## 🎥 Video de Demostración

**Duración:** 4-5 minutos

**Contenido sugerido:**

1. **Introducción (30 seg)**
   - Mostrar topología
   - Presentar nombre y matrícula
   - Explicar el objetivo

2. **Estado Inicial (45 seg)**
   - Verificar conectividad (`ping`)
   - Mostrar tabla ARP normal en víctima
   - Verificar IP forwarding

3. **Ejecución del Ataque (1.5 min)**
   - Habilitar IP forwarding
   - Iniciar captura en Wireshark
   - Ejecutar script MitM
   - Mostrar tabla ARP envenenada

4. **Interceptación de Tráfico (1 min)**
   - Generar tráfico desde la víctima
   - Mostrar captura en Wireshark
   - Demostrar que el tráfico pasa por el atacante

5. **Restauración y Mitigación (45 seg)**
   - Detener ataque con Ctrl+C
   - Verificar restauración de ARP
   - Mostrar medida de mitigación (DAI o ARP estático)

---

## 📚 Referencias y Recursos

### Documentación Oficial

- [ARP RFC 826](https://tools.ietf.org/html/rfc826)
- [Cisco DAI Configuration Guide](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst6500/ios/15-0SY/configuration/guide/15_0_sy_swcg/dynamic_arp_inspection.html)
- [Scapy Documentation](https://scapy.readthedocs.io/)

### Artículos de Seguridad

- [MITM Attacks Explained](https://www.varonis.com/blog/man-in-the-middle-attack)
- [ARP Spoofing Detection and Prevention](https://www.cisco.com/c/en/us/about/security-center/arp-spoofing.html)

### Herramientas Relacionadas

- **Ettercap:** Framework MitM completo
- **Bettercap:** Herramienta moderna de MitM
- **MITMProxy:** Proxy para analizar tráfico HTTPS
- **Wireshark:** Análisis de protocolos

---

## 🤝 Contribuciones

Este es un proyecto educativo. Las contribuciones son bienvenidas:

1. Fork el repositorio
2. Crea una branch (`git checkout -b feature/mejora`)
3. Commit tus cambios (`git commit -am 'Agregar mejora'`)
4. Push a la branch (`git push origin feature/mejora`)
5. Abre un Pull Request

---

## 📄 Licencia

Este proyecto está bajo la **Licencia MIT** - ver el archivo `LICENSE` para más detalles.

**DISCLAIMER:** El autor no se hace responsable del mal uso de esta herramienta. El uso de este código implica aceptar total responsabilidad por sus acciones.

---

## ✅ Lista de Verificación para el Laboratorio

- [ ] Topología implementada y funcional
- [ ] IP forwarding habilitado
- [ ] Script ejecutándose correctamente
- [ ] Tabla ARP de la víctima envenenada verificada
- [ ] Tráfico capturado en Wireshark
- [ ] Screenshots de todos los pasos
- [ ] Video de demostración completo
- [ ] Restauración de ARP verificada
- [ ] Medidas de mitigación documentadas
- [ ] README.md completo
- [ ] Repositorio en GitHub

---

## 📞 Contacto

- **GitHub:** [tu-usuario]
- **Email:** [tu-email]
- **Universidad:** [tu-universidad]

---

## 🔄 Actualizaciones

- **v1.0.0** (Feb 2026) - Versión inicial
  - Funcionalidad básica de ARP Spoofing
  - Restauración automática de tablas ARP
  - Documentación completa
  - Ejemplos de mitigación

---

**¡Usa este código de manera ética y responsable! La seguridad es responsabilidad de todos.** 🛡️
