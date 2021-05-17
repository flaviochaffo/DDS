library(jsonlite)
library(mitre)
library(burro)
library(dplyr)
library(ggplot2)
library(plyr)
library(markdown)
library(knitr)
library(stringr)

#CPEVULN <- function(producto){


  producto = c("Siemens","Rockwell")
  print(class(producto))
  print(producto[3])
  i = 0

  while (i<length(producto)){
    i <- i + 1
    jasons <- "https://services.nvd.nist.gov/rest/json/cpes/1.0?keyword="
    jasone <- "&addOns=cves"
    jason1 <- paste(jasons,producto[i],jasone, sep = "")

    api <- fromJSON(jason1)
    #api <- fromJSON("https://services.nvd.nist.gov/rest/json/cpes/1.0?keyword=siemens&addOns=cves") #Puedes cambiar siemens por cualquier otro producto
    total <- api$totalResults
    print(total)
    if (total <= 5000){
      api <- fromJSON(paste(jason1,"&startIndex=0&resultsPerPage=5000",sep = "")) #Obtenemos la lista completa de cpes
      }

    if (length(producto)> 1){
      vuln <- api$result$cpes$vulnerabilities  #Separamos la lista de vulnerabilidades
      cpe <- api$result$cpes  # Separamoos el dataframe de CPEs
      cpenames <- ldply(cpe$titles)  #Convertimos a dataframe la lista de CPEs
      cpenames$vuln <- vuln               #Añadimos la lista de vulnerabilidades como una columna al dataframe de CPEs
      cpenames$total <- as.numeric(lapply(cpenames[,3],length))
      suma <- sum(cpenames$total)
      if (i==1){
        vulntotal <- c(suma)
        cpetotal <- c(total)

        }
      else {
          vulntotal <- append(vulntotal,suma,after = length(vulntotal))
          cpetotal <- append(cpetotal,total,after = length(cpetotal))
            }


    } else{
        vuln <- api$result$cpes$vulnerabilities  #Separamos la lista de vulnerabilidades
        cpe <- api$result$cpes  # Separamoos el dataframe de CPEs
        cpenames <- ldply(cpe$titles)  #Convertimos a dataframe la lista de CPEs
        cpenames$vuln <- vuln               #Añadimos la lista de vulnerabilidades como una columna al dataframe de CPEs
        cpenames$total <- as.numeric(lapply(cpenames[,3],length))
        cpeordered <- cpenames[order(cpenames$total,decreasing = TRUE),]
        vulntotal <- sum(cpeordered$total)
        print(vulntotal)

        cpemorevuln <- cpeordered[1:30,]
        color <- c(1:nrow(cpemorevuln))

#        aux <- 1
#        matchstr <- cpemorevuln$title[1]

#        while (aux < nrow(cpemorevuln)-1){

#          aux <- aux + 1
#          matchstr <- str_match_all(matchstr,cpemorevuln$title[aux])

#          }

#        cpemorevuln$title <- str_remove_all(cpemorevuln$title,matchstr)
        graphic1 <- ggplot(data = cpemorevuln, mapping = aes(x = total, y = title, fill = as.factor(color)))

        graphic1 + geom_bar(stat = 'identity') +
          xlab("Total de vulnerabilidades") +
          ylab("CPE") +
          ggtitle(paste("Gráfico de los 20 CPEs más vulnerables de",producto,sep = " ")) +
          labs(fill = "CPEs")

      }
    }

  if (length(producto)>1){

    producto <- ldply(producto)
    producto$vulntotal <- vulntotal
    producto$cpetotal <- cpetotal
    producto$pond <- producto$vulntotal / producto$cpetotal
    names(producto) <- c("Name","Vulns","Cpes","Pond")
    color <- c(1:nrow(producto))
    graphic1 <- ggplot(data = producto, mapping = aes(x = Name, y = Pond, fill = as.factor(color)))

    graphic1 + geom_bar(stat = 'identity') +
      xlab("Producto") +
      ylab("Total de vulnerabilidades") +
      ggtitle("Vulnerabilidades por producto") +

        labs(fill = "CPEs")

      return(producto)

  }else{
    return(cpemorevuln)

  }
#}
