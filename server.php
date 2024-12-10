<?php 
session_start();

// Hata raporlamasını etkinleştir
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Değişken tanımlamaları
$username = "";
$email    = "";
$errors = array(); 
$_SESSION['success'] = "";

// Kullanıcı verilerini çerezden oku veya boş bir dizi oluştur
if(isset($_COOKIE['users'])) {
    $users = json_decode($_COOKIE['users'], true);
    if(!$users) {
        $users = array();
    }
} else {
    $users = array();
}

// KAYIT OLUŞTURMA
if (isset($_POST['reg_user'])) {
    // Formdan gelen verileri al
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password_1 = trim($_POST['password_1']);
    $password_2 = trim($_POST['password_2']);

    // Form doğrulama: gerekli alanların dolu olup olmadığını kontrol et
    if (empty($username)) { array_push($errors, "Kullanıcı adı gerekli"); }
    if (empty($email)) { array_push($errors, "E-posta gerekli"); }
    if (empty($password_1)) { array_push($errors, "Şifre gerekli"); }

    // Şifrelerin eşleştiğini kontrol et
    if ($password_1 != $password_2) {
        array_push($errors, "İki şifre eşleşmiyor");
    }

    // Kullanıcı adının daha önce kayıtlı olup olmadığını kontrol et
    foreach ($users as $user) {
        if ($user['username'] === $username) {
            array_push($errors, "Bu kullanıcı adı zaten alındı");
            break;
        }
    }

    // Hatalar yoksa kullanıcıyı çerezlere ekle
    if (count($errors) == 0) {
        // Şifreyi güvenli bir şekilde hash'le
        $password = password_hash($password_1, PASSWORD_DEFAULT);

        // Yeni kullanıcıyı ekle
        $new_user = array(
            'username' => $username,
            'email' => $email,
            'password' => $password
        );
        $users[] = $new_user;

        // Kullanıcı verilerini JSON formatında çerezlere kaydet
        setcookie('users', json_encode($users), [
            'expires' => time() + (86400 * 30), // 30 gün geçerli
            'path' => '/',
            'secure' => isset($_SERVER['HTTPS']), // HTTPS kullanılıyorsa Secure flag'ı ekle
            'httponly' => true, // JavaScript erişimine kapalı
            'samesite' => 'Strict', // CSRF koruması için SameSite ayarı
        ]);

        // Oturum bilgilerini ayarla
        $_SESSION['username'] = $username;
        $_SESSION['success'] = "Artık giriş yapmış durumdasınız";
        header('location: index.php');
        exit();
    }
}

// GİRİŞ YAPMA
if (isset($_POST['login_user'])) {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    if (empty($username)) {
        array_push($errors, "Kullanıcı adı gerekli");
    }
    if (empty($password)) {
        array_push($errors, "Şifre gerekli");
    }

    if (count($errors) == 0) {
        $user_found = false;

        foreach ($users as $user) {
            if ($user['username'] === $username) {
                // Şifreyi doğrula
                if (password_verify($password, $user['password'])) {
                    $user_found = true;
                    break;
                }
            }
        }

        if ($user_found) {
            $_SESSION['username'] = $username;
            $_SESSION['success'] = "Artık giriş yapmış durumdasınız";
            header('location: index.php');
            exit();
        } else {
            array_push($errors, "Yanlış kullanıcı adı/şifre kombinasyonu");
        }
    }
}
?>
