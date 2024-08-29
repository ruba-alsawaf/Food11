<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use App\Models\User;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:3',
            'name' => 'required|string|max:255',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        try {
            $userData = [
                'email' => $request->email,
                'password' => bcrypt($request->password),
                'name' => $request->name,
            ];

            $user = User::create($userData);
            Auth::login($user);  
            
            return response()->json(['message' => 'Registration successful.', 'user' => $user], 201);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Something went wrong during registration'], 500);
        }
    }
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:3',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        if (! $token = auth('api')->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->createNewToken($token);
    }

    public function logout(Request $request)
    {
        auth('api')->logout();

        return response()->json(['message' => 'User successfully signed out']);
    }

    public function me()
    {
        return response()->json(auth('api')->user());
    }

    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'user' => auth('api')->user()
        ]);
    }
}

