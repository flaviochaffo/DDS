library(jsonlite)
library(mitre)
library(burro)
library(dplyr)
library(ggplot2)
library(plyr)
library(markdown)
library(knitr)
library(stringr)


CVEordered

print(nrow(cwes))                                               #Muestro el número de filas de la tabla cwes
CVEaux <- CVEordered[-grep("NVD",CVEordered[,9]),]            #Elimino todas las filas que no contengan CWE
CWES <- data.frame(CVEaux[,9])              #Llevo solo la columna de CWE ID a un nuevo dataframe
colnames(CWES) <- "CWEs"                  #Le coloco de nombre a la columna CEWS
i = 1
while (i <= nrow(cwes)){

  try({                                               #
      aux <- grep(CWES[i,1],cwes$Code_Standard)     #Busco donde se encuentra el CWEID de la tabla CVE en la tabla de CWEs
      CWES$CWEs[i] <- cwes$Code_Standard[aux]       #Copio el código CWE
      CWES$Name[i] <- cwes$Name[aux]                #Copio su nombre, descripción y su CAPEC
      CWES$Description[i] <- cwes$Description[aux]
      CWES$CAPEC[i] <- cwes$Related_Attack_Patterns[aux]

       }, silent = TRUE
      )                                             #Oculto los errores para que no malogre el flujo
  i <- i + 1


}

aux <- nrow(CWES)                               #Cuento todas las líneas de CWEs

CAPEC <- data.frame(str_split(CWES$CAPEC[1],","))                 #Llevo a un nuevo dataframe todas los CVEs del primer CPE
#CAPEC <- unlist(strsplit(CAPEC$CAPEC[1], split=':', fixed=TRUE))[2]
colnames(CAPEC) <- "CAPEC"                               #Le pongo de nombre a la columna CVEs
i <- 2                                                #Auxiliar en 2

while (i <= aux){                                     #Voy añadiendo al dataframe anterior todas las listas de CVEs que existen en el dataframe CPE

  CAPEC2 <- data.frame(str_split(CWES$CAPEC[i],","))
  colnames(CAPEC2) <- "CAPEC"
  CAPEC <- rbind(CAPEC,CAPEC2)
  distinct(CAPEC)
  i <- i + 1
}

i <- 1


while (i <= nrow(CAPEC)){                                     #Voy añadiendo al dataframe anterior todas las listas de CVEs que existen en el dataframe CPE

  test <- unlist(strsplit(CAPEC[i,1], split=':', fixed=TRUE))[2]
  CAPEC[i,1] <- substr(test,3,str_length(test)-1)

  try({
    if(grep('"',CAPEC[i,1])>0){CAPEC[i,1] <- substring(CAPEC[i,1],1,str_length(CAPEC[i,1])-3)}

    },silent = TRUE)

  if (is.na(CAPEC[i,1])){

    CAPEC[i,1] <- 0
  }
  CAPEC$ID[i] <- CAPEC[i,1]
  if (CAPEC[i,1] != 0)
    {

    CAPEC[i,1] <- paste("CAPEC-",CAPEC[i,1],sep="")
      }
  i <- i + 1
}



i <- 2

while (i <= nrow(CAPEC)){
  j <- i - 1

  while (j > 0){

    if (CAPEC[i,1] == CAPEC[j,1]){

      CAPEC[i,1] <- 0
    }
    j <- j - 1

  }

  i <- i + 1
}

CAPECf <- data.frame(CAPEC[1,])
colnames(CAPECf) <- c("CAPEC","ID")
i <- 2

while (i <= nrow(CAPEC)){

  if(CAPEC[i,1] != 0){
    CAPECf <- rbind(CAPECf,CAPEC[i,])
  }

  i <- i + 1
}
CAPECf$total <- lapply(lapply(CAPECf[,2],CWES$CAPEC,FUN = grep), length)
CAPECf$pos <- lapply(CAPECf[,2],CWES$CAPEC,FUN = grep)
CAPECf$total <- as.numeric(CAPECf[,3])
CAPECordered <- CAPECf[order(CAPECf$total,decreasing = TRUE),]

TOPCAPEC <- CAPECordered[1:40,]
color <- c(1:nrow(TOPCAPEC))

graphic1 <- ggplot(data = TOPCAPEC, mapping = aes(x = total, y = CAPEC, fill = as.factor(total)))

graphic1 + geom_bar(stat = 'identity') +
  xlab("Total de Debilidades") +
  ylab("CAPEC") +
  ggtitle(paste("Gráfico de los TOP 40 Amenazas en",producto,sep = " ")) +
  labs(fill = "CAPECs")

capecs.patterns <- file.show("capec.patterns.rda")
