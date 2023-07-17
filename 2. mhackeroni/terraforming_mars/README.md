# Terraforming Mars

**Category**: "Aerocapture the Flag"

### Dashboard info

> The Galactic Mining and Tunneling Corporation (GMAT) is back in action. This time we've extended our operations to include a terraforming base on the planet Mars. We have a communication satellite inbound but our orbit mechanics guy went on vacation and won't answer his phone or email, how inconsiderate.
>
> Calculate the maneuvers to keep the satellite in contact with the terraforming base and we will reward you with a flag.

### Prompt

Reachable with: `nc mars.quals2023-kah5Aiv9.satellitesabove.me 5300`

```Please put our communication satellite in contact with the terraforming colony
You may assume all celestial bodies are point masses
The orbital elements for the satellite with respect to the Mars Centered ICRF frame:
Gregorian TT: 01 Oct 2024 12:00:00.000
Semimajor axis: -4782.646575482534 km
Eccentricity: 4.562837706706173
Inclination: 25.85702674260729 deg
RAAN: 243.2894523568879 deg
Argument of periapsis: 167.6140637297613 deg
True Anomaly: 260 deg
--------------------------------------------
The terraformer is at:
Latitude: 40.8 deg
Longitude: -9.6 deg
--------------------------------------------
Provide a list of maneuvers that will keep the satellite in contact with our terraforming station on mars
If your manuevers are valid you can view the trajectory at 35.172.250.82:25183
You can manuever as many times as you want but you only have 2.8 km/s of ∆V
Maneuver Times is in Gregorian UTC:  YYYY-MM-DD HH:MM:SS.sss
Manuevers are in Mars Centered Intertial Coordinate system
Input your manuevers in the following format:
Time,∆Vx,∆Vy,∆VZ
Enter 'DONE' when you want have added all your maneuvers
Input next maneuver:
```

## Description

The prompt data completely defines an hyperbolic orbit ($e$ccentricity$>1$) around Mars.

The objective of the challenge is identifying an [aerostationary orbit](http://en.wikipedia.org/wiki/Areostationary_orbit) for the satellite, in view of the terraforming station, and subsequently maneuver to it (without depleting the propellant).

After some failed attempts the organizers informed us of two additional limitations:
- the satellite needs to contact the station before 2024-10-4 12:00:00 UTC;
- the satellite needs to maintain uninterrupted contact for an entire year;

### Feedback

After a valid submissions, a webpage with a [cesium](http://cesium.com/) view of Mars shows you a simulation, with a ground view available.

## Solution

### Tools

We used the [poliastro](http://docs.poliastro.space/en/stable/) python library to plot the orbits and compute the maneuvers. It depends on [astropy](http://www.astropy.org/).

Manipulation of vectors has been done with [numpi](http://numpy.org/).

To write the script and interact with the output we used [Jupyter Notebook](http://jupyter-notebook.readthedocs.io/en/stable/index.html).

### Strategy

After setting up the Jupyter notebook, the first step is to visualize the initial orbit:
![Initial trajectory](./images/01.png)

We easily notice the high energy of the orbit and know that most of our propellant will be spent in breaking to close it.

Before starting to compute maneuvers, we compute the radius of an aerostationary orbit. This is easily accomplished with Kepler's third law, using the planetary constant of Mars ($\mu=4.2828314 \cdot 10^4 \mathsf{\frac{km^3}{s^2}}$ from Jet Propulsion Laboratory Development Ephemeris 405) and the duration of a sidereal martian day ($24.6229\mathsf{h}$ [according to NASA](http://nssdc.gsfc.nasa.gov/planetary/factsheet/marsfact.html)).
$$ T = 2\pi \sqrt{\frac{a^3}{\mu}} \quad\implies\quad r=a=\sqrt[3]{\mu\left(\frac{T}{2\pi}\right)^2}=20427.591\mathsf{km}$$
*More on this number later.*

From this point on we tried a couple of different approaches, failing to respect the propellant constraint or the (initially unknown) time constraints.

In the winning strategy, four impulses are commanded:
1. Brake at the pericenter of the hyperbola, to enter a low eccentricity orbit (in a previous iteration we tried a circular orbit, but this proved too fuel-consuming).
2. Change of plane at the ascending node, bringing the satellite in an equatorial orbit:
![](./images/02.png)
3. At the pericenter of this equatorial orbit initiate a bitangent trasfer to an aerostationary orbit:
![](./images/03.png)
4. At the apocenter of the transfer orbit terminate the transfer by circularizing:
![](./images/04.png)

By sheer luck the relative position of the satellite on the final orbit is in view of the terraforming station, otherwise a phasing maneuver would be necessary.

Here is a table with time, impulses and cost of each maneuver (values are rounded):

|         Time          | $\Delta \overrightarrow{v} \mathsf{\frac{km}{s}}$     | $\|\Delta \overrightarrow{v}\| \mathsf{\frac{km}{s}}$ |
|:---------------------:|:-----------------------------------------------------:|:-----------------------------------------------------:|
| 2024-10-03 05:06:11.5 | $\begin{bmatrix}1.429\\ -1.217\\ 0.884\end{bmatrix}$  | $2.075$                                               |
| 2024-10-03 17:03:35.0 | $\begin{bmatrix}0.123\\ -0.058\\ -0.593\end{bmatrix}$ | $0.608$                                               |
| 2024-10-04 03:04:02.8 | $\begin{bmatrix}0.008\\ -0.007\\ 0\end{bmatrix}$      | $0.01$                                                |
| 2024-10-04 13:50:56.9 | $\begin{bmatrix}0.051\\ -0.043\\ 0\end{bmatrix}$      | $0.066$                                               |

And here are all maneuvers in a single image:

![final trajectory](./images/05.png)


#### A note on the Aerostationary radius

For some reason, the previous value of $r=20427.591\mathsf{km}$ is wrong, using this value in the organizers' simulation gives an orbit that is slower than the surface of Mars. This is probably due to some different planetary data.
To obtain the correct value (according to the organizers) we iterated on different submissions, visually checking if the resulting orbit was faster (value too low) or slower (value too high) than the surface of Mars.
In the end, we got the flag with $r=20370\mathsf{km}$.

## Solution script

See the [Python Jupyter notebook here](./terraforming_mars.ipynb).
