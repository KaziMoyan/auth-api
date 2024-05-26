<?php
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\Api\ApiController;

// Register
Route::post('register', [ApiController::class, 'register']);

// Login
Route::post('/login', [ApiController::class, 'login']);

// Group routes that require authentication
Route::middleware('auth:sanctum')->group(function() {
    // Profile
    Route::get('profile', [ApiController::class, 'profile']);
    
    // Logout
    Route::post('logout', [ApiController::class, 'logout']);
});
