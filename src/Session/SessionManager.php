<?php
namespace Clover\Session;

use Clover\Session\Interfaces\SessionInterface;
use Clover\Session\Enums\SessionStatus;
use Clover\Session\Security\TokenManager;

/**
 * Secure, production-ready session manager
 */
final class SessionManager implements SessionInterface {
    private SessionStatus $status;
    private int $expire = 604800; // 7 days
    private string $path = '/';
    private bool $secure = true;
    private bool $autoStart = true;

    public function __construct(bool $autoStart = true) {
        $this->autoStart = $autoStart;
        if ($autoStart) $this->start();
    }

    // Fluent API
    public function expire(int $days): static { $this->expire = $days*86400; return $this; }
    public function path(string $path): static { $this->path = $path; return $this; }
    public function secure(bool $secure = true): static { $this->secure = $secure; return $this; }
    public function autoStart(bool $flag = true): static { $this->autoStart = $flag; return $this; }

    public function start(): void {
        if ($this->autoStart && session_status() !== PHP_SESSION_ACTIVE) {
            session_set_cookie_params([
                'lifetime' => $this->expire,
                'path'     => $this->path,
                'domain'   => '',
                'secure'   => $this->secure,
                'httponly' => true,
                'samesite' => 'Strict'
            ]);

            ini_set('session.use_strict_mode','1');
            ini_set('session.use_only_cookies','1');
            ini_set('session.gc_maxlifetime',(string)$this->expire);

            session_start();

            // Fingerprint
            $fingerprint = hash('sha256',($_SERVER['REMOTE_ADDR']??'').($_SERVER['HTTP_USER_AGENT']??''));
            if (!isset($_SESSION['_fingerprint'])) $_SESSION['_fingerprint'] = $fingerprint;
            elseif ($_SESSION['_fingerprint'] !== $fingerprint) { $this->destroy(); exit("Session hijack detected."); }

            // Auto destroy inactive sessions
            if (isset($_SESSION['_last_activity']) && (time()-$_SESSION['_last_activity']>$this->expire)) $this->destroy();
            $_SESSION['_last_activity'] = time();

            // Tokens
            if (!isset($_SESSION['_session_token'])) $_SESSION['_session_token'] = TokenManager::generateToken();
            if (!isset($_SESSION['_csrf_token'])) $_SESSION['_csrf_token'] = TokenManager::generateToken();

            $this->status = SessionStatus::ACTIVE;
        }
    }

    public function create(string $key, mixed $value): void { $_SESSION[$key]=$value; }
    public function get(string $key, mixed $default=null): mixed { return $_SESSION[$key]??$default; }
    public function key(string $key): array { return [$key=>$_SESSION[$key]??null]; }
    public function update(string $key, mixed $value): void { if(isset($_SESSION[$key])) $_SESSION[$key]=$value; }
    public function delete(string $key): void { unset($_SESSION[$key]); }
    public function destroy(): void { session_unset(); session_destroy(); $this->status=SessionStatus::DESTROYED; }
    public function regenerate(): void { session_regenerate_id(true); $_SESSION['_session_token']=TokenManager::generateToken(); $this->status=SessionStatus::REGENERATED; }
    public function getStatus(): SessionStatus { return $this->status; }
}
