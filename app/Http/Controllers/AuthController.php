<?php

namespace App\Http\Controllers;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;


class AuthController extends Controller
{
    /**
     * Registration
     *
     * @param Request $request
     * @return void
     */
    public function register(Request $request){
        
        $fields = $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|unique:users,email',
            'password' => 'required|string|confirmed'

        ]);

        $user = User::create([
            'name' => $fields['name'],
            'email' =>$fields['email'],
            'password' => bcrypt($fields['password'])
        ]);

        $token = $user->createToken('my_app_token')->plainTextToken;

        $response = [
            'user' => $user,
            'token' =>$token
        ];

        return response($response, 201);
    }
    
    /**
     * Login
     *
     * @param Request $request
     * @return void
     */
    public function login(Request $request){
        
        $fields = $request->validate([
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        //Check email
        $user = User::where('email', $fields['email'])->first();

        //Check Password
        if(!$user || !Hash::check($fields['password'], $user->password)){
            return response([
                'message' => 'Bad Credentials'
            ],401);
        }

        $token = $user->createToken('my_app_token')->plainTextToken;

        $response = [
            'user' => $user,
            'token' => $token
        ];

        return response($response, 201);
    }

    /**
     * user logout
     *
     * @param Request $request
     * @return void
     */
    public function logout(Request $request){
        
        auth()->user()->tokens()->delete();

        return [
            'message' => 'Token Destroy/Logged out.'
        ];
    }

}
