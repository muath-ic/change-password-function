<?php 
public function changeUserPassword(Request $request) {

    if(!isset($request->user_id)){
        abort(403);
    }
    $user = User::where('email',$request->user_id)->first();

    if (empty($user) || Auth::user()->cant('update', $user)) {
        abort(403);
    }
    $messages = [
        'admin_password.required' => Lang::get('validation.user_password_required'),
        'user_password_new.required' => Lang::get('validation.user_password_required'),
        'user_password_new.confirmed' => Lang::get('validation.password_not_match'),
    ];

    $validator = Validator::make($request->all(), [
        'admin_password' => 'required',
        'user_password_new' => 'required|confirmed',
    ], $messages);

    if ($validator->fails()) {
        return back()->withErrors($validator)
                    ->withInput();
    }

    if (Auth::user()->isSuperAdmin() && Hash::check($request->admin_password, Auth::user()->password)) {

        $user->password = Hash::make($request->user_password_new);
        $user->save();

        // Log this Operation
        $this->logOperation(
            Lang::get('logs.change_user_pass', ['name' => Auth::user()->name, 'user' =>  $user->name]),
            Auth::user()->id,
            "users",
            $user->id
        );


        return redirect('admin/users')
        ->with('status',Lang::get('general.updated_successfully'));
    }else{
        return back()->withErrors(Lang::get('validation.password_not_match'))
                ->withInput();
    }
}