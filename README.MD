install the dependency

1. 
npm i express mongoose cookie-parser express-session bcryptjs jsonwebtoken ejs express-validator multer body-parser nodemon

2. 
const express = require('express')

3.
app = express() 
app.listen()

3. 
mongoose.connect("url").then(()=>{connect}).cathc((err))

4. 
const User = mongoose.model('User', new mongoose.Schema({
    email:String
}))

5. 
app.use(express.json())
app.use(bosyParse.urlencoded({extends:true}))

6. 
app.post('/register',async (req,res)=>{
    const hashPass = await bcrypt.hash(req.body.pass,10)
    await User.create({
        email:req.body.email,
        pass:hashPass
    })

    res.json({
        res.send({
            msg:"Data added".
        })
    })
})

7. 
app.post(/login',async(req,res)=>{
   const user= await User.findOne({
        email: req.body.email
    })

    if(!user){
        res.json({msg:"404"})
    }
    if(bcrypt.compare(req.body.pass, user.pass)){
        res.json({msg:"401"})
    }
    res.json({msg:"Login Successfully", data:await jwt.sign({email:user.email}, "secrateByAdi7", {expireIn:"60M"})})
})

8. 
app.post("/update", async (req,res)=>{
    const hashPass = await bcrypt.hash(req.body.pass, 10)
   const user = User.findOneAndUpdate(
        {email:req.body.email},
        {pass:hashPass}
        {req.body}
    )
    if(!user){
        res.json({msg:"404"})
    }
    res.json({msg:"data updated", data:user})
})