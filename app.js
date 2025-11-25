const bodyParser = require('body-parser');
const { urlencoded } = require('body-parser');
const express = require('express')
const mongoose = require('mongoose')
const jwt = require("jsonwebtoken")
const bcrypt = require("bcryptjs");
const multer = require('multer');
const cookieParser = require('cookie-parser')
const session = require('express-session')
const ejs = require('ejs')
const path = require('path')


const app = express()

mongoose.connect("mongodb://localhost:27017/userCrd").then(() => {
    console.log("DB connected");
}).catch((err) => {
    console.log("DB con error: " + err);
})

const User = mongoose.model('User', new mongoose.Schema({
    email: String,
    pass: String,
    photos: [String]
}))

app.use(express.json())
app.use(bodyParser.urlencoded({ extended: false }))
app.use(cookieParser())
app.use(session({
    secret: "mySecretKey",
    resave: false,
    saveUninitialized: true,
    cookie: { maxAge: 60 * 60 * 1000 }
}));

app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"));
app.use("/uploads", express.static("uploads"));

const storage = multer.diskStorage({
    destination: "uploads/",
    filename: (req, res, cb) => {
        cb(null, Date.now() + "-" + res.originalname)
    }
})

const uploads = multer({ storage })

app.get('/hello', (req, res) => {
    res.json({
        message: 'Hello World!'
    })
    // res.send("Hello")
})

app.get("/register", async (req, res) => {
    res.render("register", { data: null, msg: null })
})

app.post('/register', async (req, res) => {
    const hashPass = await bcrypt.hash(req.body.pass, 10)

    await User.create({
        email: req.body.email,
        pass: hashPass,
    })

    res.render("login", { data: null, msg: "Registration successfully done you can login now." })
})


app.post("/upload", uploads.single("photo"), (req, res) => {
    res.json({ msg: "Photo uploaded", photo: req.file })
})

app.post("/uploads-multipule", uploads.array("photos", 3), async (req, res) => {
    const checkToken = req.cookies.jwt || req.session.jwt;
    if (!checkToken) return res.redirect("/");

    let decoded;
    try {
        decoded = jwt.verify(checkToken, "secrateByAdi7");
    } catch (err) {
        return res.redirect("/");
    }

    const user = await User.findOne({ email: decoded.email });
    if (!user) return res.redirect("/");

    user.photos = req.files.map(file => file.filename);
    await user.save();

    res.redirect("/profile");
});


app.get("/", (req, res) => {
    res.render("login", { data: null, msg: null })
})

app.post("/login", async (req, res) => {
    const loginUser = await User.findOne({
        email: req.body.email
    })

    if (!loginUser) return res.render("login", { msg: "User not found" })

    const okPass = await bcrypt.compare(req.body.pass, loginUser.pass)

    if (!okPass) return res.render("login", { msg: "Invalid pass" })

    const token = await jwt.sign({ id: loginUser._id, email: loginUser.email }, "secrateByAdi7", { expiresIn: "60M" })

    res.cookie("jwt", token)
    req.session.jwt = token;
    res.redirect("profile");
})


app.get("/allData", async (req, res) => {
    const allData = await User.find()
    if (!allData) {
        res.json({ msg: "no data" })
    }

    res.json({ data: allData })
})


app.get("/profile", async (req, res) => {
    const checkToken = req.cookies.jwt || req.session.jwt;
    if (!checkToken) {
        return res.render("/", { data: null, msg: "Not logged in" });
    }

    let decoded;
    try {
        decoded = jwt.verify(checkToken, "secrateByAdi7");
    } catch (err) {
        return res.render("/", { data: null, msg: "Invalid token" });
    }

    const user = await User.findOne({ email: decoded.email });
    if (!user) {
        return res.render("/", { data: null, msg: "User not found" });
    }

    res.render("profile", { data: user, msg: "Data fetched" });
});

app.get("/delete", async (req, res) => {
    res.redirect('/')
})
app.post("/delete", async (req, res) => {
    const user = await User.findOneAndDelete({
        email: req.body.email
    })

    if (!user) {
        res.json({ msg: "404" })
    }
    res.redirect('/register')
})


app.get("/update", async (req, res) => {
    const checkToken = req.cookies.jwt || req.session.jwt
    if (!checkToken) return res.redirect("/")

    let decoded
    try {
        decoded = jwt.verify(checkToken, "secrateByAdi7")
    } catch (error) {
        return res.redirect("/")
    }

    const user = await User.findOne({ email: decoded.email })
    if (!user) return res.redirect("/")

    res.render("update", { data: user, msg: null })
})

app.post("/update", async (req, res) => {
    const hashPass = await bcrypt.hash(req.body.pass, 10)

    const user = await User.findOneAndUpdate(
        { email: req.body.email },
        { pass: hashPass },
        req.body,
        { new: true }
    )

    if (!user) {
        res.json({ msg: "404" })
    }
    res.render("profile", { data: user, msg: null })
})

app.get("/logout", async (req, res) => {
    res.clearCookie("token")
    req.session.destroy()
    res.redirect("/")
})

app.listen(5000, () => console.log("server started"))

/*

<% if(msg){%>
        <p>
            <%= msg %>
        </p>
        <%} %>
            <form action="/register" method="post">
                Email: <input type="text" name="email"> <br>
                Password <input type="password" name="pass"> <br>
                <input type="submit" value="Submit">
            </form>
            If you an acount! <a href="/">Click Here</a>

 <% if(msg){ %>
        <p>
            <%= msg %>
        </p>
        <% } %>

            <form action="/login" method="post">
                Email: <input type="text" name="email"> <br>
                Password <input type="password" name="pass"> <br>
                <input type="submit" value="Login">
            </form>
            If you don't have an acount! <a href="register">Click Here</a>

            
<h3>Your Photos:</h3>
<% if(data.photos && data.photos.length> 0){ %>
    <% data.photos.forEach(photo=> { %>
        <img src="/uploads/<%= photo %>" width="100" style="margin:5px;">
        <% }) %>
            <% } else { %>
                <p>No photos uploaded</p>
                <% } %>

                    <form action="/uploads-multipule" method="post" enctype="multipart/form-data">
                        Upload Photos (max 3):
                        <input type="file" name="photos" multiple required>
                        <input type="submit" value="Upload">
                    </form>


<?php

session_start();

$code = rand(0000, 9999);
$_SESSION['captcha_code'] = $code;

header("Content-Type: image/png");

$img = imagecreatetruecolor(120, 40);
$txt = imagecolorallocate($img, 240, 240, 240);

imagestring($img, 5, 35, 14, $code, $txt);

imagepng($img);
imagedestroy($img);




<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    if ($_SESSION["captcha_code"] != $_POST["captcha"]) {
        echo "Incorrect captcha";
        exit;
    }

    $data = [
        "email" => $_POST["email"],
        "pass" => $_POST["pass"]
    ];

    $curl = curl_init("http://localhost:5000/login");

    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($curl, CURLOPT_HTTPHEADER, [
        "Content-Type: application/json"
    ]);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

    $res = curl_exec($curl);
    $data = json_decode($res);

    if (isset($data->success) && $data->success == true) {

        $_SESSION["token"] = $data->token;

        header("Location: data.php");
        exit;
    } else {
        echo $data->msg ?? "Login failed";
    }
}
?>

<form method="POST">
    Email : <input type="email" name="email" /><br>
    Pass : <input type="password" name="pass" /><br>
    <img src="captcha.php" /><br>
    Enter Captcha Code : <input name="captcha" />
    <input type="submit" value="Login">
</form>



<?php
session_start();

if ($_SERVER["REQUEST_METHOD"] == "POST") {

    if ($_SESSION["captcha_code"] != $_POST["captcha"]) {
        echo "Incorrect captcha";
    }

    $data = [
        "email" => $_POST["email"],
        "pass" => $_POST["pass"]
    ];

    $curl = curl_init("http://localhost:5000/register");

    curl_setopt($curl, CURLOPT_POST, true);
    curl_setopt($curl, CURLOPT_POSTFIELDS, json_encode($data));
    curl_setopt($curl, CURLOPT_HTTPHEADER, ["Content-Type: application/json"]);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

    $res = curl_exec($curl);

    $data = json_decode($res);
    echo $data->message;
}

?>


<form method="POST">
    Email : <input type="email" name="email" /><br>
    Pass : <input type="pass" name="pass" /><br>
    <img src="captcha.php" /><br>
    Enter Captcha Code : <input name="captcha" />
    <input type="submit" value="Register">
</form>



<?php
session_start();

if (!isset($_SESSION["token"])) {
    header("Location: login.php");
    exit;
}
?>
<h1>Welcome back, <?php echo $data['email']; ?></h1>

<p>
    <?php echo $msg; ?>
</p>

<h3>Your Photos:</h3>

<?php if (!empty($data['photos']) && count($data['photos']) > 0) { ?>

    <?php foreach ($data['photos'] as $photo) { ?>
        <img src="/uploads/<?php echo $photo; ?>" width="100" style="margin:5px;">
    <?php } ?>

<?php } else { ?>
    <p>No photos uploaded</p>
<?php } ?>

<form action="/uploads-multipule" method="post" enctype="multipart/form-data">
    Upload Photos (max 3):
    <input type="file" name="photos[]" multiple required>
    <input type="submit" value="Upload">
</form>

const Category = mongoose.model('Category', new mongoose.Schema({
    name: String
}));

const Product = mongoose.model('Product', new mongoose.Schema({
    name: String,
    price: Number,
    category: {
        type: mongoose.Schema.ObjectId,
        ref: "Category",
        required: true
    },
    photo: String
}));


app.get('/category/add', async (req, res) => {
    res.render('category', { message: "" });
})

app.post('/category/add', async (req, res) => {

    await Category.create({
        name: req.body.name
    });

    res.render('category', { message: "Category Added" });
})

app.get("/product/add", async (req, res) => {
    const categories = await Category.find();

    res.render("add", { categories: categories, message: "" });
})

app.post("/product/add", upload.single("photo"), async (req, res) => {
    const { name, price, category } = req.body;

    console.log("FILE" + req.file);
    const photo = req.file ? req.file.path : null;

    const pr = await Product.create({
        name: name,
        price: price,
        photo: photo,
        category: category
    })

    const products = await Product.find().populate('category');

    res.render('product', { products });

})

app.get('/', async (req, res) => {
    const products = await Product.find().populate('category');

    res.render('product', { products });
})

app.get('/product/get', async (req, res) => {
    const products = await Product.find().populate('category');

    res.json(products);
})

app.get('/product/delete/:id', async (req, res) => {
    const product = await Product.findOne({ _id: req.params.id });

    if (product && product.photo) {
        fs.unlink(product.photo, (err) => {
            console.log(err);
        })
    }

    await Product.deleteOne({
        _id: product._id
    })

    const products = await Product.find().populate('category');
    res.render('product', { products });

})


 Add Product <br><br>

    <form action="/product/add" method="post" enctype="multipart/form-data">
        Name : <input type="text" name="name"><br>
        Price : <input type="number" name="price"><br>
        Category : <select name="category">
            <option value="">Select Category</option>
        <% categories.forEach(element => { %>
            <option value="<%= element._id %>"><%= element.name %></option>
        <% }); %>
        </select><br>
        Product Image : <input type="file" name="photo"/><br>
        <input type="submit" value="Add Product" />
    </form>
    

 <h3>Products</h3>

    <a href="/product/add">Add Product</a>
    <a href="/category/add">Add Category</a>

    <table>
        <thead>
            <tr>
                <th>Image</th>
                <th>Name</th>
                <th>Category</th>
                <th>Price</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
            <% products.forEach(element=> { %>
                <tr>
                    <td><img src="/<%= element.photo %>" width="100" height="100" /></td>
                    <td>
                        <%= element.name %>
                    </td>
                    <td>
                        <%= element.category.name %>
                    </td>
                    <td>
                        <%= element.price %>
                    </td>
                    <td>
                        <a href="/product/delete/<%= element._id %>">Delete</a>
                    </td>
                </tr>

                <% }); %>
        </tbody>
    </table>

    <?php

$host = "localhost";
$user = "root";
$pass = "";
$dbname = "demo_db";

$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die(json_encode(["success" => false, "msg" => "DB Connection failed"]));
}

?>



const axios = require("axios");

app.get("/users", async (req, res) => {
    try {
        const response = await axios.get("http://localhost/api/get_users.php");

        res.render("users", { data: response.data });

    } catch (err) {
        res.send("Error: " + err.message);
    }
});


<h1>Registered Users</h1>

<table border="1" cellpadding="10">
    <tr>
        <th>ID</th>
        <th>Name</th>
        <th>Email</th>
    </tr>

    <% if (data.length > 0) { %>
        <% data.forEach(user => { %>
            <tr>
                <td><%= user.id %></td>
                <td><%= user.name %></td>
                <td><%= user.email %></td>
            </tr>
        <% }) %>
    <% } else { %>
        <tr>
            <td colspan="3">No users found.</td>
        </tr>
    <% } %>
</table>



<?php
header("Content-Type: application/json");
include "db.php";

$input = json_decode(file_get_contents("php://input"), true);

$name = $input["name"] ?? null;
$email = $input["email"] ?? null;

if (!$name || !$email) {
    echo json_encode(["success" => false, "msg" => "Missing fields"]);
    exit;
}

$stmt = $conn->prepare("INSERT INTO users (name, email) VALUES (?, ?)");
$stmt->bind_param("ss", $name, $email);

if ($stmt->execute()) {
    echo json_encode(["success" => true, "msg" => "User saved successfully"]);
} else {
    echo json_encode(["success" => false, "msg" => "Insert failed"]);
}
?>



app.post("/add-user", async (req, res) => {
    const { name, email } = req.body;

    try {
        const response = await axios.post(
            "http://localhost/api/save_data.php",
            { name, email },
            { headers: { "Content-Type": "application/json" } }
        );

        res.render("result", { msg: response.data.msg });

    } catch (error) {
        res.render("result", { msg: "Error: " + error.message });
    }
});


<h2>Add User</h2>

<form action="/add-user" method="POST">
    Name: <input type="text" name="name" required><br><br>
    Email: <input type="email" name="email" required><br><br>

    <button type="submit">Save</button>
</form>


*/

