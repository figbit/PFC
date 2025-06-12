# KPMG-PFCG Pentest Bulgu Kartı Oluşturucu

Penetrasyon test ekipleri için Nessus XML dosyalarını profesyonel Word belgelerine dönüştüren Docker konteynerli web uygulaması.

## 🚀 Hızlı Başlangıç

### Ön Gereksinimler
- Docker Desktop yüklü
- Git (GitHub'dan klonlamak için)

### 1. GitHub'dan Klonla
```bash
git clone https://github.com/figbit/PFCG.git
cd PFCG
```

### 2. Tek Komutla Çalıştır

**Windows:**
```batch
deploy.bat
```

**Linux/Mac:**
```bash
chmod +x deploy.sh
./deploy.sh
```

**Manuel Docker:**
```bash
docker-compose up -d --build
```

### 3. Uygulamaya Erişim
Tarayıcınızı açın ve şu adrese gidin:
```
http://localhost:1881
```

## 📖 Kullanım

1. .nessus XML dosyanızı yükleyin (maks 100MB)
2. Müşteri kısaltmasını girin
3. Ağ türünü seçin (İç/Dış)
4. "Bulgu Kartı Oluştur" tıklayın
5. Oluşturulan DOCX raporunu indirin

## 🐳 Docker Komutları

```bash
# Başlat
docker-compose up -d

# Durdur
docker-compose down

# Logları görüntüle
docker-compose logs -f

# Yeniden başlat
docker-compose restart
```

## 🔧 Sorun Giderme

### Linux'ta İzin Hatası
Eğer "Permission denied" hatası alıyorsanız:

```bash
# Konteyner durdurun
docker-compose down

# Son değişiklikleri çekin
git pull origin main

# Eski imajları silin ve yeniden oluşturun
docker-compose down --rmi all
docker-compose up --build -d
```

### Upload Klasörü İzin Sorunu
Hala sorun devam ediyorsa:

```bash
# Host sistemde klasörler oluşturun
sudo mkdir -p uploads downloads
sudo chmod 777 uploads downloads
```

## ⚠️ Önemli

- Yalnızca yetkili penetrasyon testleri için
- Kullanıcılar dosya güvenliğinden sorumludur
- Kullanmadan önce uygun yetkilendirme sağlayın

---

**Erişim:** http://localhost:1881 | **Port:** 1881 | **Dil:** Türkçe 