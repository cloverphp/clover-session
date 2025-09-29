## Session
Clover PHP: Session


```php 
use Clover\Session\SessionManager;

$session = (new SessionManager(false)) // do not auto-start in constructor
    ->expire(7)
    ->path('/')
    ->secure(true)
    ->autoStart(true); // sets flag to autoStart

$session->start(); // start separately, cannot chain
```
