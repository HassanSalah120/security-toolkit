# CRITICAL SECURITY FIXES FOR INSOMNIA GAMING EGYPT
## IMMEDIATE ACTION REQUIRED - PROMO CODE DATA EXPOSURE

---

## 🚨 VULNERABILITIES FOUND

### 1. **CORS MISCONFIGURATION (CRITICAL)**
**Problem:** API allows requests from ANY domain
- Access-Control-Allow-Origin: https://evil.com (reflects attacker origin)
- **Impact:** Any malicious website can enumerate promo codes through visitors' browsers
- **Fix:** Restrict CORS to your domain only

### 2. **DEBUG ENDPOINT EXPOSED (CRITICAL)**
**Problem:** `/debug/events/1/promo-codes` endpoint exists
- May return raw database data or debug information
- **Impact:** Could expose ALL promo codes directly
- **Fix:** Remove all debug endpoints from production

### 3. **API DOCUMENTATION EXPOSED (HIGH)**
**Problem:** `/swagger.json` and `/openapi.json` are public
- Exposes full API schema including all endpoints
- **Impact:** Attackers know exactly how to query your API
- **Fix:** Require authentication for API docs or remove from production

### 4. **BACKUP FILE ACCESSIBLE (CRITICAL)**
**Problem:** `/backup.sql` endpoint exists
- **Impact:** Database backup contains ALL promo codes
- **Fix:** Block access to all backup/log files

### 5. **PROMO CODE ENUMERATION (CRITICAL)**
**Problem:** The original issue - response differentiation allows brute force
- **Impact:** 180 req/min × unlimited time = all codes discovered
- **Fix:** See Laravel fix below

---

## 🔧 IMMEDIATE FIXES

### FIX 1: Restrict CORS (nginx.conf)
```nginx
# Remove this (DANGEROUS):
add_header 'Access-Control-Allow-Origin' '*';

# Use this:
add_header 'Access-Control-Allow-Origin' 'https://insomniagamingegypt.com';
add_header 'Access-Control-Allow-Methods' 'GET, POST, OPTIONS';
add_header 'Access-Control-Allow-Headers' 'Content-Type, Authorization';
add_header 'Access-Control-Allow-Credentials' 'true';
```

### FIX 2: Block Debug Endpoints (nginx.conf)
```nginx
# Block all debug endpoints
location ~ ^/(debug|_debug|api/debug|api/dev|api/test)/ {
    deny all;
    return 404;
}

# Block API documentation
location ~ ^/(swagger|openapi|api/docs|api/documentation)\.?(json|yaml)?$ {
    deny all;
    return 404;
}

# Block backup/log files
location ~ \.(sql|log|env|backup|zip|tar|gz)$ {
    deny all;
    return 404;
}

# Block sensitive paths
location ~ ^/(storage/logs|storage/framework|config|\.env) {
    deny all;
    return 404;
}
```

### FIX 3: Laravel Routes (routes/api.php)
```php
<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\PromoCodeController;

// REMOVE THIS VULNERABLE ENDPOINT:
// Route::get('/public/events/{event_id}/promo-codes/{code}', [PromoCodeController::class, 'validate']);

// REPLACE WITH SECURE VERSION - Only callable during checkout:
Route::post('/orders/apply-promo', [PromoCodeController::class, 'apply'])
    ->middleware(['auth:sanctum', 'throttle:5,1']); // 5 attempts per minute, requires auth

// Admin-only endpoint for listing codes (if needed):
Route::get('/admin/events/{event_id}/promo-codes', [PromoCodeController::class, 'list'])
    ->middleware(['auth:sanctum', 'can:view-promo-codes']);
```

### FIX 4: Secure Promo Code Controller
```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\PromoCode;
use App\Models\Order;

class PromoCodeController extends Controller
{
    /**
     * SECURE: Apply promo code during checkout
     * - Requires authenticated session
     * - Rate limited per user
     * - Returns generic response (no information leak)
     */
    public function apply(Request $request)
    {
        $validated = $request->validate([
            'code' => 'required|string|max:255',
            'order_id' => 'required|exists:orders,id',
        ]);
        
        $code = strtoupper($validated['code']);
        $order = Order::find($validated['order_id']);
        
        // SECURITY: Verify order belongs to authenticated user
        if ($order->user_id !== auth()->id()) {
            return response()->json([
                'success' => false,
                'message' => 'Unable to apply code'  // GENERIC - no info leak
            ], 403);
        }
        
        $promoCode = PromoCode::where('code', $code)
            ->where('event_id', $order->event_id)
            ->where('expires_at', '>', now())
            ->where('uses_remaining', '>', 0)
            ->first();
        
        // CRITICAL: Same response structure for valid/invalid
        if (!$promoCode) {
            return response()->json([
                'success' => false,
                'applied' => false,
                'discount_amount' => 0,
                'message' => 'Code could not be applied'  // GENERIC
            ]);
        }
        
        // Apply the code
        $discount = $promoCode->calculateDiscount($order->total);
        
        return response()->json([
            'success' => true,
            'applied' => true,
            'discount_amount' => $discount,
            'message' => 'Code applied successfully'
        ]);
    }
    
    /**
     * NEVER expose a public endpoint that validates codes
     * This was the original vulnerability
     */
}
```

### FIX 5: Environment Configuration (.env)
```env
# Production settings
APP_ENV=production
APP_DEBUG=false

# Rate limiting
RATE_LIMIT_PROMO_CODE=5  # 5 attempts per minute per user

# Security headers
SECURITY_HEADERS_ENABLE=true

# Disable debug endpoints
DEBUG_ENDPOINTS_ENABLED=false
```

### FIX 6: Middleware for Security Headers
```php
<?php

namespace App\Http\Middleware;

use Closure;

class SecurityHeaders
{
    public function handle($request, Closure $next)
    {
        $response = $next($request);
        
        // Remove server fingerprinting
        $response->headers->remove('X-Powered-By');
        
        // Add security headers
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('X-XSS-Protection', '1; mode=block');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Content-Security-Policy', "default-src 'self'");
        $response->headers->set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
        
        return $response;
    }
}
```

### FIX 7: Register Middleware (app/Http/Kernel.php)
```php
protected $middleware = [
    // ... other middleware
    \App\Http\Middleware\SecurityHeaders::class,
];
```

---

## 📋 DEPLOYMENT CHECKLIST

Before deploying to production:

- [ ] Remove all debug endpoints from routes
- [ ] Update nginx.conf with security blocks
- [ ] Set APP_DEBUG=false in .env
- [ ] Set APP_ENV=production in .env
- [ ] Enable SecurityHeaders middleware
- [ ] Test that /swagger.json returns 404
- [ ] Test that /backup.sql returns 404
- [ ] Test that /debug/ returns 404
- [ ] Verify CORS only allows your domain
- [ ] Verify old promo code endpoint is disabled
- [ ] Test new checkout flow works correctly
- [ ] Invalidate all existing promo codes and generate new random ones
- [ ] Set up monitoring for suspicious activity

---

## 🚨 CODE GENERATION FIX

Your codes currently follow a pattern `3DS6-XXXX-XXXX`. This is dangerous because:
- Predictable prefix reduces search space by 99.999%
- Attackers only need to brute-force 8 characters, not 12

### Generate Secure Random Codes:
```php
// Instead of: 3DS6-8ZSG-1SEZ (predictable prefix)
// Use: X7K9M2P4Q8R5 (fully random, no pattern)

function generateSecurePromoCode($length = 16) {
    $characters = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';  // No I, O, 0, 1 (confusing chars)
    $code = '';
    
    for ($i = 0; $i < $length; $i++) {
        $code .= $characters[random_int(0, strlen($characters) - 1)];
    }
    
    return $code;
}

// Example: "X7K9M2P4Q8R5T6Y3"
```

---

## 📞 IF YOU NEED HELP

1. **Immediate:** Disable the vulnerable endpoint NOW:
   ```bash
   # Add to nginx.conf emergency block
   location /api/public/events/1/promo-codes {
       deny all;
       return 404;
   }
   ```
   Then reload nginx: `sudo systemctl reload nginx`

2. **Monitor:** Watch your logs for enumeration attempts:
   ```bash
   tail -f /var/log/nginx/access.log | grep "promo-codes"
   ```

3. **Invalidate:** All existing codes may be compromised. Generate new random ones.

---

**THIS IS A BUSINESS-CRITICAL SECURITY ISSUE. FIX IMMEDIATELY.**
