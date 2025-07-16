<!DOCTYPE html>
<html>
    <head>
      <title> Introduction to Object-Oriented Programming </title>
    </head>
	<body>
      <p>
      <?php
        // Create the Class
        class Person {
            // Create Properties - (Variables tied to objects)
            public $firstne;
            public $lastne;
            public $age;
            
            // Assigning Values to the Property Variables
            public function __construct($firstne, $lastne, $age) {
              $this->firstne = $firstne;
              $this->lastne = $lastne;
              $this->age = $age;
            }
            
            // Create a Method (Function tied to an Object)
            public function hello() {
              return "I am " . $this->firstne . " " . $this->lastne . ", my age is: " . $this->age . "";
            }
        }
          
        // Creating a new person ned "John Smith", who is 25 years old
        $person1 = new Person('John', 'Smith', 25);
		$person2 = new Person('Joe', 'Bob', 35);
        
        // Print out what the hello method returns
        echo $person1->hello(); 
		echo "<br>";
		echo $person2->hello(); 
        ?>
        </p>
    </body>
</html>