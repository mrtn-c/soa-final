//Inicio MQTT.
const dotenv = require('dotenv');
dotenv.config();
const mqtt = require('mqtt');
const clientId = `mqtt_${Math.random().toString(16).slice(3)}`

const connectUrl = `${process.env.HOST}:${process.env.PORT_MOSQUITTO}`

const client = mqtt.connect(connectUrl, {
    clientId,
    clean: true,
    connectTimeout: 4000,
    reconnectPeriod: 1000,
})
  
client.on('connect', () => {
    console.log('Connected')
    //Limpieza del mensaje recibido de mqtt.
    client.subscribe("/id/limpiar");
    client.subscribe("/listo");
    //Login
    client.subscribe("/login/auth");
    //Verificacion, de usuarios no repetidos.
    client.subscribe("/user/register/valid/email");
    client.subscribe("/user/register/valid/usuario");
})


const jwt = require('jsonwebtoken');
const express = require("express");
const bcrypt = require('bcrypt');

const app = express()

//cargo entorno y corro app
let port = process.env.PORT || 3000;
app.use(express.json());
app.listen(port, () => {
    console.log("Server Listening on PORT:", port); 
});


app.post("/user/login", async (req, res) => {

  try{
    client.publish("/login", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
      if (error) {
        console.log(error)
        console.error(error)
      }
    });

  }catch{
    res.send("Error a publicar en mqtt, intente nuevamente");
    res.status(409).send("Conflicto");
  }

  let nodeRes;

  try{
    nodeRes = await waitForValidation();
  }catch{
    res.status(401).send("Usuario no encontrado, intente nuevamente");
    return;
  }

  
  // encriptado contraseña...
  bcrypt.compare(req.body.contrasenia, nodeRes.contrasenia, (err, result) => {
    if (err) {
      console.error('Error al comparar las contraseñas:', err);
      res.status(409).send("Conflicto");
    
    } else if (result) {
      console.log('Las contraseñas coinciden. El usuario puede iniciar sesión.');
      let jwtSecretKey = process.env.JWT_SECRET_KEY;
      let data = {
        time: Date(),
        userId: nodeRes.id,
      }
  
      const token = jwt.sign(data, jwtSecretKey);
    
      res.status(200).json(token);
      // Aquí es donde normalmente procederías con la lógica para iniciar sesión o permitir el acceso del usuario
    } else {
      console.log('Las contraseñas no coinciden. El usuario no puede iniciar sesión.');
      res.status(404).send("Contraseña incorrecta");
      // Aquí es donde normalmente mostrarías un mensaje de error al usuario o tomarías alguna acción adicional
    }
  });    
});

//Valido que el usuario existe -> " app.post("/user/login") "
const waitForValidation = () => {
    
  return new Promise((resolve, reject) => {
    client.on('message', (topic, message) => {
      if (topic === '/login/auth') {
        try{
          jsonString = message.toString().match(/\[(.*?)\]/);
          const response = JSON.parse(jsonString[1]);
          if(response.id !== null){
            resolve(response);
          } else {
            
            reject();
          }
        }catch (e){
          reject();
        }
      }
    });
  });

};

//Registrar USUARIO
app.post("/user/registro", async (req, res) => {
  try {
    const { nombre, apellido, email, usuario, contrasenia, habilitado, rol } = req.body;

    // Validar que todos los campos obligatorios estén presentes
    if (!nombre || !apellido || !email || !usuario || !contrasenia || !rol) {
      return res.status(400).json({ message: "Todos los campos son obligatorios." });
    }

    // Validar el formato y el no uso del email
    const emailValido = await isValidEmail(email);
    if(emailValido === 1){
      console.log("email en uso!")
      return res.status(400).send("email ya en uso.");
    } else if(emailValido === 2){
      return res.status(409).send("Conflicto");
    }
    

    // if (!isValidEmail(email)) {
    //   return res.status(400).json({ message: "El email ingresado no es válido." });
    // }
    const usuarioValido = await isValidUsuario(usuario);
    if(usuarioValido === 1){
      return res.status(400).send("Nombre de usuario ya en uso.");
    } else if(emailValido === 2){
      return res.status(409).send("Conflicto");
    }


    // Validar que la contraseña tenga al menos 8 caracteres
    try {
      if (contrasenia.length < 8) {
        return res.status(400).json({ message: "La contraseña debe tener al menos 8 caracteres." });
      } else {

        req.body.contrasenia = await bcrypt.hash(contrasenia, 10) 
      }
    }catch{
      return res.status(400).json({ message: "Error al almacenar contraseña, intente nuevamente." });
    }


    // Validar que el rol sea uno de los roles permitidos (admin, user, operador, etc.)
    const rolesPermitidos = [1, 2, 3, 4];
    if (!rolesPermitidos.includes(rol)) {
      return res.status(400).json({ message: "El rol ingresado no es válido." });
    }

    req.body.habilitado = 1;
    console.log(JSON.stringify(req.body));
    try{
      client.publish("/user/register", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
        if (error) {
          console.log(error)
          console.error(error)
        }
      });
  
    }catch{
      res.send("Error a publicar en mqtt, intente nuevamente");
      res.status(409).send("Conflicto");
    }
  


    // Por último, envías una respuesta de éxito si todo está bien
    res.status(201).json({ message: "Usuario registrado con éxito." });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Error en el servidor." });
  }
});

async function isValidUsuario(usuario){
  let valid = false;
  try{
    console.log(JSON.stringify(usuario));
    client.publish("/user/register/check/usuario", JSON.stringify(usuario), { qos: 0, retain: false }, (error) => {
      if (error) {
        console.log(error)
        console.error(error)
      }
    });
    
    try{
      valid = await waitForValidUsuario();
      return 0;
    }catch{
      return 1;
    }
  
  }catch (error){
    return 2;
  }

}

const waitForValidUsuario = () => {
    
  return new Promise((resolve, reject) => {
    client.on('message', (topic, message) => {
      if (topic === '/user/register/valid/usuario') {
        try{
          const cantidad = JSON.parse(message).cantidad;
          console.log(cantidad);
          if(cantidad === 0){
            resolve();
          } else {            
            reject();
          }
        }catch (e){
          reject();
        }
      }
    });
  });

};


// Función para validar el formato del email
async function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(emailRegex.test(email)){
    try{
      client.publish("/user/register/check/email", JSON.stringify(email), { qos: 0, retain: false }, (error) => {
        if (error) {
          console.log(error)
          console.error(error)
        }
      });
      
      try{
        valid = await waitForValidEmail();//0
        return 0;
      }catch{
        console.log("ingreso al 1 email")
        return 1; //1
      }
    
    }catch{
      console.log("ingreso al 2 email");
      return 2;
      // res.send("Error a publicar en mqtt, intente nuevamente");
        // res.status(409).send("Conflicto");//2
    }
  }
  
}

const waitForValidEmail = () => {
    
  return new Promise((resolve, reject) => {
    client.on('message', (topic, message) => {
      if (topic === '/user/register/valid/email') {
        try{
          const cantidad = JSON.parse(message).cantidad;
          console.log(cantidad);
          if(cantidad === 0){
            resolve(true);
          } else {
            
            reject();
          }
        }catch (e){
          reject();
        }
      }
    });
  });

};
//DATOS BIOMETRICOS...
app.post('/user/register/face', async (req, res) => {
  const userId = verificarToken(req.header('Authorization'));
  if(userId===true){
    return res.status(401).json({ mensaje: 'Token inválido.' });
  } else if(userId === false){
    return res.status(401).json({ mensaje: 'Acceso denegado. No se proporcionó un token.' });
  }
  
  try{

  
  client.publish("/user/register/face", JSON.stringify(userId), { qos: 0, retain: false }, (error) => {
      if (error) {
        console.log(error)
        console.error(error)
      }
  });
  }catch (error){
      console.error('Error:', error);
      res.status(500).send('Error en el servidor');
  }    

});



app.post("/dummy", (req, res) => {
  const token = verificarToken(req.header('Authorization'));
  if(token===true){
    return res.status(401).json({ mensaje: 'Token inválido.' });
  } else if(token === false){
    return res.status(401).json({ mensaje: 'Acceso denegado. No se proporcionó un token.' });
  }

  res.send({"token": token});
});

//Espero el ID del recipiente que acabo de registrar. " app.post('/identificacion/recipiente') "
const waitForId = () => {
    return new Promise((resolve, reject) => {
      client.on('message', (topic, message) => {
        if (topic === '/listo') {
          jsonString = message.toString().match(/\[(.*?)\]/);
          const response = JSON.parse(jsonString[1]);
          resolve(response);
        }
      });
    });
};


//Inicia identificacion recipiente. PASO 1.
//FLOW -> identificacion recipiente
app.post('/identificacion/recipiente', async (req, res) => {
  const token = verificarToken(req.header('Authorization'));
  if(token===true){
    return res.status(401).json({ mensaje: 'Token inválido.' });
  } else if(token === false){
    return res.status(401).json({ mensaje: 'Acceso denegado. No se proporcionó un token.' });
  }
  
  try {
      // Publicar el cuerpo en un topic MQTT
    client.publish("/inicio/carga", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
      if (error) {
        console.log(error)
        console.error(error)
      }
    });
  
      // Esperar hasta recibir la respuesta del MQTT
    const response = await waitForId();
  
      // Enviar la respuesta al cliente
    res.status(200).json(response);
  } catch (error) {
      console.error('Error:', error);
      res.status(500).send('Error en el servidor');
  }
});


//Inicia control. PASO 2.
//Recibe ID recipiente.
//Toma 10 medidas, promedio es la altura del recipiente.
//FLOW -> mugiwara
app.post('/control/inicio', async (req, res) => {
  const token = verificarToken(req.header('Authorization'));
  if(token===true){
    return res.status(401).json({ mensaje: 'Token inválido.' });
  } else if(token === false){
    return res.status(401).json({ mensaje: 'Acceso denegado. No se proporcionó un token.' });
  }  
  
  
  try{

    
    client.publish("/control/inicio", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
        if (error) {
          console.log(error)
          console.error(error)
        }
    });
    }catch (error){
        console.error('Error:', error);
        res.status(500).send('Error en el servidor');
    } 
    
    res.status(200).send("Control Iniciado con Exito");

});

//Inicia control. PASO 2.
//recibe ID, radio, altura recipiente.  
app.post('/test', async (req, res) => {
  const token = verificarToken(req.header('Authorization'));
  if(token===true){
    return res.status(401).json({ mensaje: 'Token inválido.' });
  } else if(token === false){
    return res.status(401).json({ mensaje: 'Acceso denegado. No se proporcionó un token.' });
  }
  
  try{

  
  client.publish("/empezar/control", JSON.stringify(req.body), { qos: 0, retain: false }, (error) => {
      if (error) {
        console.log(error)
        console.error(error)
      }
  });
  }catch (error){
      console.error('Error:', error);
      res.status(500).send('Error en el servidor');
  }    

});


//Limpio ID para continuar flujo.
client.on('message',function(topic, message, packet){   
    
  if(topic === '/id/limpiar'){
        jsonString = message.toString().match(/\[(.*?)\]/); //pregunta

        console.log(jsonString[1] == '');
        
        if(jsonString[1] !== ''){
            jsonParsed = JSON.parse(jsonString[1]);
            console.log(jsonParsed);
            client.publish("/id/recipiente", JSON.stringify(jsonParsed)  , { qos: 0, retain: false }, (error) => {
                if (error) {
                    console.log(error)
                    console.error(error)
                    }
                })
        }
        
    }
   
});


//Verifico Token JWT. Para cada peticion.
const verificarToken = (token) => {
  if (!token) {
    return false;
    
  }
  // Eliminamos el prefijo "Bearer " del token
  const tokenSinBearer = token.replace('Bearer ', '');

  try {
    const datosToken = jwt.verify(tokenSinBearer, process.env.JWT_SECRET_KEY); //DEVUELVE ID Y DATE.
    console.log(datosToken);
    return datosToken.userId;
  } catch (error) {
    return true;
    
  }
};