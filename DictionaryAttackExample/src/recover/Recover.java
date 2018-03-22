package recover;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

public class Recover 
{
	static int passwordCounter = 0;
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException 
	{
		String hashFileName = args[1];
		File hashFile = new File("H:\\workspace\\Coursework1_CSC8102\\src\\recover\\" + hashFileName);
		
		//Defines path for the file to be found, creates a file with what is contained in args[3]
		PrintWriter foundPasswords = new PrintWriter("H:\\workspace\\Coursework1_CSC8102\\src\\recover\\" + args[3]);
		
		//Text file containing all names in boy file
		Path dictionaryBoyNames = Paths.get("H:\\workspace\\Coursework1_CSC8102\\src\\recover\\boy_names.txt");
		
		 //Text file containing all names in girl file
		Path dictionaryGirlNames = Paths.get("H:\\workspace\\Coursework1_CSC8102\\src\\recover\\girl_names.txt");
		
		//Text file containing all English words. Renamed to all_moby_words.txt
		Path dictionaryWords = Paths.get("H:\\workspace\\Coursework1_CSC8102\\src\\recover\\word_list_moby_all_moby_words.flat.txt");
		
		//Counters for keeping track of number of hashes analyzed and passwords found and list which adds passwords as they are discovered. List used to prevent looping into alphanumeric char generator.
		int hashesAnalyzed = 0;
		ArrayList<String> allFoundPasswords = new ArrayList<String>();
		
		Path hashes = hashFile.toPath();
		
		long startTime = System.currentTimeMillis();
		
		//First try block looks through hash files, then compares all hashes to the names. Then, it collects all possible permutations
		//of the names plus all possible 4-digit number combinations at the end. Then, it checks for all possible 4-character combinations.
		//Then, it checks the dictionaryWords file for all words.
		if (args[0].equals("-i") && args[2].equals("-o"))
		{
			try (BufferedReader hashesReader = Files.newBufferedReader(hashes, StandardCharsets.UTF_8)) 
			{
			    while (true) 
				{
			        String hashPassword = hashesReader.readLine();
			        
			        if (hashPassword == null) 
					{
			           break;
			        }
			        
			        hashesAnalyzed++;
			        
			        System.out.println("Working on... " + hashPassword);
			        
			        boolean boyNameFound = findNames(dictionaryBoyNames, hashPassword, foundPasswords, allFoundPasswords);
			        boolean girlNameFound = findNames(dictionaryGirlNames, hashPassword, foundPasswords, allFoundPasswords);
			        
			        //If the hash is neither a boy or girl name, look into words
			        if(boyNameFound == false && girlNameFound == false)
			        {
				        try (BufferedReader dictionaryWordsReader = Files.newBufferedReader(dictionaryWords, StandardCharsets.UTF_8)) 
				        {
				            while (true) 
				            {
				                String dictionaryWord = dictionaryWordsReader.readLine();
				                if (dictionaryWord == null)
				                {
				                   break;
				                }
				                
								String hashedDictionaryWord = hashWord(dictionaryWord);
								
								if(hashPassword.equals(hashedDictionaryWord))
								{
							    	foundPasswords.println(hashPassword + " " + dictionaryWord);
							    	incrementPasswordCounter();
							    	allFoundPasswords.add(hashPassword);
							    	break;
								}
				            }
				        }
			        }
			        
			        //To prevent looping into the char generator after a password is found
			        if(!allFoundPasswords.contains(hashPassword))
			        {
			        //For finding all 4-digit alphnumeric combinations
			        String allComb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890_!@#$%^&*'";
			        String word;
					for (int i = 0; i < allComb.length(); i++)
					{
					    for (int j = 0; j < allComb.length(); j++)
					    {
					        for (int k = 0; k < allComb.length(); k++)
					        {
					            for (int l = 0; l < allComb.length(); l++)
					            {					
					                word = allComb.charAt(i) + "" + allComb.charAt(j) + "" + allComb.charAt(k) + "" + allComb.charAt(l); 
					                String hashedPW = hashWord(word);
					                if(hashedPW.equals(hashPassword))
					                {
					                	foundPasswords.println(hashedPW + " " + word);
					                	passwordCounter++;
					                	allFoundPasswords.add(hashPassword);
			        					break;
					                }
					            }
					        }
					    }
					}
			        }
			    }
			} catch (NoSuchFileException e) 
			{
				System.out.println("Hashes file could not be found ");
			}
		} 
		else
		{
			System.out.println("Incorrect command(s). Please type in -i and -o for first and third arguments.");
		}
		
		foundPasswords.close();
		long endTime   = System.currentTimeMillis();
		long totalTime = endTime - startTime;
		System.out.println("Hashes Analyzed: " + hashesAnalyzed + " Passwords found: " + passwordCounter + " Execution time: " + totalTime/1000 + "s");
		
		
	}
	
	/**
	  * Hashes string and converts to hexadecimal.
	  * @return finalHashedWord
	  */
	public static String hashWord(String word) throws NoSuchAlgorithmException
	{
		MessageDigest digest = MessageDigest.getInstance("SHA-256");
		digest.update(word.getBytes());
		byte[] hashedWord = digest.digest();
		
		//Change to hexadecimal
		StringBuffer string = new StringBuffer();
	    for (int i = 0; i < hashedWord.length; i++) 
	    {
	    	 string.append(Integer.toString((hashedWord[i] & 0xff) + 0x100, 16).substring(1));
	    }
	    
	    String finalHashedWord = string.toString().toUpperCase();
	    
	    return finalHashedWord;
	}
	
	/**
	 * Method for finding names in the text files. Returns true if a name is found, false if not. Looks at all permutations of a name for each line in the dictionary.
	 * @param names
	 * @param hashPassword
	 * @param foundPasswords
	 * @param passwordCounter
	 * @param allFoundPasswords
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public static boolean findNames(Path names, String hashPassword, PrintWriter foundPasswords, ArrayList<String> allFoundPasswords) throws IOException, NoSuchAlgorithmException
	{
        try (BufferedReader dictionaryNamesReader = Files.newBufferedReader(names, StandardCharsets.UTF_8)) 
        {
            while (true)
            {
                String dictionaryName = dictionaryNamesReader.readLine();
                if (dictionaryName == null)
                {
                   return false;
                }
                
				String hashedDictionaryName = hashWord(dictionaryName);
				
				if(!allFoundPasswords.contains(hashedDictionaryName))
				{
				if(hashPassword.equals(hashedDictionaryName))
				{
			    	foundPasswords.println(hashPassword + " " + dictionaryName);
			    	incrementPasswordCounter();
			    	allFoundPasswords.add(hashPassword);
			    	return true;
				}
				
				//Permutes string for all case combinations
				int numOfCombos = 1 << dictionaryName.length();  

				if(!allFoundPasswords.contains(hashedDictionaryName))
				{
				for (int i = 0; i < numOfCombos; i++) 
				{
				    char[] nameCombinations = dictionaryName.toCharArray();
				    for (int j = 0; j < dictionaryName.length(); j++) 
				    {
				        if (((i >> j) & 1) == 1 ) 
				        {
				            nameCombinations[j] = Character.toUpperCase(dictionaryName.charAt(j));
				        }
				    }
				
	                //Counter for adding 0000-9999 to the permuted string
				    for (int counter=0; counter <= 9999; counter++)
				    {
				    	String counterString = Integer.toString(counter);
				    	String nameCombo = String.valueOf(nameCombinations);
					    String nameNum = nameCombo + counterString;
					    String hashedNameNum = hashWord(nameNum);

					    if(hashPassword.equals(hashedNameNum))
					    {
					    	foundPasswords.println(hashPassword + " " + nameNum);
					    	incrementPasswordCounter();
					    	allFoundPasswords.add(hashPassword);
					    	return true;
					    }
				    }
				}
				}
            }
            }
            
        }
	}
	
	/**
	 * Used to increment the password counter
	 * @return passwordCounter
	 */
	public static int incrementPasswordCounter()
	{
		return passwordCounter++;
	}
	

}
