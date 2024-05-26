<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;

class ApiController extends Controller
{
    public function register(Request $request)
    {
        try {
            // Validate the request
            $validateUser = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|min:6', // Ensure password has a minimum length
            ]);

            // If validation fails, return error response
            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateUser->errors()
                ], 422);
            }

            // Create a new user
            $user = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password), // Hash the password before saving
            ]);

            // Return success response with API token
            return response()->json([
                'status' => true,
                'message' => 'User created successfully',
                'token' => $user->createToken("API Token")->plainTextToken
            ], 201);
        } catch (\Throwable $th) {
            // Return error response in case of exception
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500);
        }
    }

    public function login(Request $request)
    {
        try {
            // Validate the request
            $validateUser = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required|min:6', // Ensure password has a minimum length
            ]);

            // If validation fails, return error response
            if ($validateUser->fails()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Validation error',
                    'errors' => $validateUser->errors()
                ], 422);
            }

            // Attempt to log the user in
            if (!Auth::attempt($request->only(['email', 'password']))) {
                return response()->json([
                    'status' => false,
                    'message' => 'Email or password is incorrect',
                ], 401);
            }

            $user = User::where('email', $request->email)->first();

            // Return success response with API token
            return response()->json([
                'status' => true,
                'message' => 'User logged in successfully',
                'token' => $user->createToken("API Token")->plainTextToken
            ], 200);

        } catch (\Throwable $th) {
            // Return error response in case of exception
            return response()->json([
                'status' => false,
                'message' => $th->getMessage(),
            ], 500);
        }
    }

    public function profile()
    {
        $user = auth()->user();
        return response()->json([
            'status' => true,
            'message' => 'Profile information',
            'user' => $user,
        ], 200);
    }

    public function logout()
    {
        auth()->user()->tokens()->delete();
        return response()->json([
            'status' => true,
            'message' => 'User logged out successfully',
        ], 200);
    }
}

