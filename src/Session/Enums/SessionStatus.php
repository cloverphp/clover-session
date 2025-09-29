<?php
namespace Clover\Session\Enums;

/**
 * Enum for session status
 */
enum SessionStatus: string {
    case INACTIVE = 'inactive';
    case ACTIVE = 'active';
    case REGENERATED = 'regenerated';
    case DESTROYED = 'destroyed';
}
